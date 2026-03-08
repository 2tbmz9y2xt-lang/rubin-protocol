package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type devnetRPCState struct {
	syncEngine  *node.SyncEngine
	blockStore  *node.BlockStore
	mempool     *node.Mempool
	peerManager *node.PeerManager
	announceTx  func([]byte) error
	nowUnix     func() uint64
	metrics     *rpcMetrics
}

type runningDevnetRPCServer struct {
	addr   string
	server *http.Server
}

type rpcMetrics struct {
	mu             sync.Mutex
	routeStatus    map[string]uint64
	submitByResult map[string]uint64
}

type getTipResponse struct {
	HasTip          bool    `json:"has_tip"`
	Height          *uint64 `json:"height"`
	TipHash         *string `json:"tip_hash"`
	BestKnownHeight uint64  `json:"best_known_height"`
	InIBD           bool    `json:"in_ibd"`
}

type getBlockResponse struct {
	Hash      string `json:"hash"`
	Height    uint64 `json:"height"`
	Canonical bool   `json:"canonical"`
	BlockHex  string `json:"block_hex"`
}

type submitTxRequest struct {
	TxHex string `json:"tx_hex"`
}

type submitTxResponse struct {
	Accepted bool   `json:"accepted"`
	TxID     string `json:"txid,omitempty"`
	Error    string `json:"error,omitempty"`
}

func newDevnetRPCState(
	syncEngine *node.SyncEngine,
	blockStore *node.BlockStore,
	mempool *node.Mempool,
	peerManager *node.PeerManager,
	announceTx func([]byte) error,
) *devnetRPCState {
	return &devnetRPCState{
		syncEngine:  syncEngine,
		blockStore:  blockStore,
		mempool:     mempool,
		peerManager: peerManager,
		announceTx:  announceTx,
		nowUnix:     nowUnixU64,
		metrics:     newRPCMetrics(),
	}
}

func newRPCMetrics() *rpcMetrics {
	return &rpcMetrics{
		routeStatus:    make(map[string]uint64),
		submitByResult: make(map[string]uint64),
	}
}

func (m *rpcMetrics) note(route string, status int) {
	if m == nil {
		return
	}
	key := route + "|" + strconv.Itoa(status)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routeStatus[key]++
}

func (m *rpcMetrics) noteSubmit(result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.submitByResult[result]++
}

func (m *rpcMetrics) snapshot() (map[string]uint64, map[string]uint64) {
	if m == nil {
		return map[string]uint64{}, map[string]uint64{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	routeStatus := make(map[string]uint64, len(m.routeStatus))
	for key, value := range m.routeStatus {
		routeStatus[key] = value
	}
	submitByResult := make(map[string]uint64, len(m.submitByResult))
	for key, value := range m.submitByResult {
		submitByResult[key] = value
	}
	return routeStatus, submitByResult
}

func startDevnetRPCServer(
	ctx context.Context,
	bindAddr string,
	state *devnetRPCState,
	stdout, stderr io.Writer,
) (*runningDevnetRPCServer, error) {
	if strings.TrimSpace(bindAddr) == "" {
		return nil, nil
	}
	if state == nil {
		return nil, errors.New("nil devnet rpc state")
	}
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Handler:           newDevnetRPCHandler(state),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && stderr != nil {
			_, _ = fmt.Fprintf(stderr, "rpc server failed: %v\n", err)
		}
	}()
	addr := listener.Addr().String()
	if stdout != nil {
		_, _ = fmt.Fprintf(stdout, "rpc: listening=%s\n", addr)
	}
	return &runningDevnetRPCServer{addr: addr, server: server}, nil
}

func (s *runningDevnetRPCServer) Close(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func newDevnetRPCHandler(state *devnetRPCState) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/get_tip", func(w http.ResponseWriter, r *http.Request) {
		handleGetTip(state, w, r)
	})
	mux.HandleFunc("/get_block", func(w http.ResponseWriter, r *http.Request) {
		handleGetBlock(state, w, r)
	})
	mux.HandleFunc("/submit_tx", func(w http.ResponseWriter, r *http.Request) {
		handleSubmitTx(state, w, r)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		handleMetrics(state, w, r)
	})
	return mux
}

func handleGetTip(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/get_tip"
	if r.Method != http.MethodGet {
		writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
			Accepted: false,
			Error:    "GET required",
		})
		return
	}
	if state == nil || state.syncEngine == nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
			Accepted: false,
			Error:    "sync engine unavailable",
		})
		return
	}
	bestKnown := state.syncEngine.BestKnownHeight()
	inIBD := state.syncEngine.IsInIBD(state.now())
	height, tipHash, ok, err := tipFromBlockStore(state.blockStore)
	if err != nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
			Accepted: false,
			Error:    err.Error(),
		})
		return
	}
	if !ok {
		writeJSONResponse(state, route, w, http.StatusOK, getTipResponse{
			HasTip:          false,
			Height:          nil,
			TipHash:         nil,
			BestKnownHeight: bestKnown,
			InIBD:           inIBD,
		})
		return
	}
	tipHex := hex.EncodeToString(tipHash[:])
	writeJSONResponse(state, route, w, http.StatusOK, getTipResponse{
		HasTip:          true,
		Height:          &height,
		TipHash:         &tipHex,
		BestKnownHeight: bestKnown,
		InIBD:           inIBD,
	})
}

func handleGetBlock(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/get_block"
	if r.Method != http.MethodGet {
		writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
			Accepted: false,
			Error:    "GET required",
		})
		return
	}
	if state == nil || state.blockStore == nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
			Accepted: false,
			Error:    "blockstore unavailable",
		})
		return
	}
	query := r.URL.Query()
	heightRaw := strings.TrimSpace(query.Get("height"))
	hashRaw := strings.TrimSpace(query.Get("hash"))
	if (heightRaw == "" && hashRaw == "") || (heightRaw != "" && hashRaw != "") {
		writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
			Accepted: false,
			Error:    "exactly one of height or hash is required",
		})
		return
	}

	var (
		height    uint64
		blockHash [32]byte
		ok        bool
		err       error
	)
	if heightRaw != "" {
		height, err = strconv.ParseUint(heightRaw, 10, 64)
		if err != nil {
			writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
				Accepted: false,
				Error:    "invalid height",
			})
			return
		}
		blockHash, ok, err = state.blockStore.CanonicalHash(height)
		if err != nil {
			writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
				Accepted: false,
				Error:    err.Error(),
			})
			return
		}
		if !ok {
			writeJSONResponse(state, route, w, http.StatusNotFound, submitTxResponse{
				Accepted: false,
				Error:    "block not found",
			})
			return
		}
	} else {
		blockHash, err = parseHex32Value(hashRaw)
		if err != nil {
			writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
				Accepted: false,
				Error:    "invalid hash",
			})
			return
		}
		height, ok, err = state.blockStore.FindCanonicalHeight(blockHash)
		if err != nil {
			writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
				Accepted: false,
				Error:    err.Error(),
			})
			return
		}
		if !ok {
			writeJSONResponse(state, route, w, http.StatusNotFound, submitTxResponse{
				Accepted: false,
				Error:    "block not found",
			})
			return
		}
	}

	blockBytes, err := state.blockStore.GetBlockByHash(blockHash)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeJSONResponse(state, route, w, http.StatusNotFound, submitTxResponse{
				Accepted: false,
				Error:    "block not found",
			})
			return
		}
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
			Accepted: false,
			Error:    err.Error(),
		})
		return
	}
	writeJSONResponse(state, route, w, http.StatusOK, getBlockResponse{
		Hash:      hex.EncodeToString(blockHash[:]),
		Height:    height,
		Canonical: true,
		BlockHex:  hex.EncodeToString(blockBytes),
	})
}

func handleSubmitTx(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/submit_tx"
	if r.Method != http.MethodPost {
		writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
			Accepted: false,
			Error:    "POST required",
		})
		return
	}
	if state == nil || state.mempool == nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
			Accepted: false,
			Error:    "mempool unavailable",
		})
		return
	}

	var req submitTxRequest
	body := io.LimitReader(r.Body, 2<<20)
	defer r.Body.Close()
	dec := json.NewDecoder(body)
	if err := dec.Decode(&req); err != nil {
		state.metrics.noteSubmit("bad_request")
		writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
			Accepted: false,
			Error:    "invalid JSON body",
		})
		return
	}
	if err := ensureJSONBodyEOF(dec); err != nil {
		state.metrics.noteSubmit("bad_request")
		writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
			Accepted: false,
			Error:    "invalid JSON body",
		})
		return
	}
	raw, err := decodeHexPayload(req.TxHex)
	if err != nil {
		state.metrics.noteSubmit("bad_request")
		writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
			Accepted: false,
			Error:    err.Error(),
		})
		return
	}
	_, txid, _, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) {
		state.metrics.noteSubmit("rejected")
		writeJSONResponse(state, route, w, http.StatusUnprocessableEntity, submitTxResponse{
			Accepted: false,
			Error:    "transaction rejected",
		})
		return
	}
	if err := state.mempool.AddTx(raw); err != nil {
		status, result := classifySubmitErr(err)
		state.metrics.noteSubmit(result)
		writeJSONResponse(state, route, w, status, submitTxResponse{
			Accepted: false,
			Error:    err.Error(),
		})
		return
	}
	if state.announceTx != nil {
		_ = state.announceTx(raw)
	}
	state.metrics.noteSubmit("accepted")
	writeJSONResponse(state, route, w, http.StatusOK, submitTxResponse{
		Accepted: true,
		TxID:     hex.EncodeToString(txid[:]),
	})
}

func handleMetrics(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/metrics"
	if r.Method != http.MethodGet {
		writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
			Accepted: false,
			Error:    "GET required",
		})
		return
	}
	body := renderPrometheusMetrics(state)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
	if state != nil && state.metrics != nil {
		state.metrics.note(route, http.StatusOK)
	}
}

func renderPrometheusMetrics(state *devnetRPCState) string {
	var (
		tipHeight       float64
		bestKnownHeight float64
		inIBD           float64
		peerCount       float64
		mempoolTxs      float64
		routeStatus     map[string]uint64
		submitByResult  map[string]uint64
	)
	if state != nil && state.syncEngine != nil {
		bestKnownHeight = float64(state.syncEngine.BestKnownHeight())
		if state.syncEngine.IsInIBD(state.now()) {
			inIBD = 1
		}
		if height, _, ok, err := tipFromBlockStore(state.blockStore); err == nil && ok {
			tipHeight = float64(height)
		}
	}
	if state != nil && state.peerManager != nil {
		peerCount = float64(len(state.peerManager.Snapshot()))
	}
	if state != nil && state.mempool != nil {
		mempoolTxs = float64(state.mempool.Len())
	}
	if state != nil && state.metrics != nil {
		routeStatus, submitByResult = state.metrics.snapshot()
	} else {
		routeStatus = map[string]uint64{}
		submitByResult = map[string]uint64{}
	}

	var lines []string
	lines = append(lines,
		"# HELP rubin_node_tip_height Current canonical tip height.",
		"# TYPE rubin_node_tip_height gauge",
		fmt.Sprintf("rubin_node_tip_height %.0f", tipHeight),
		"# HELP rubin_node_best_known_height Best known height recorded by sync engine.",
		"# TYPE rubin_node_best_known_height gauge",
		fmt.Sprintf("rubin_node_best_known_height %.0f", bestKnownHeight),
		"# HELP rubin_node_in_ibd Whether the node currently considers itself in IBD (0 or 1).",
		"# TYPE rubin_node_in_ibd gauge",
		fmt.Sprintf("rubin_node_in_ibd %.0f", inIBD),
		"# HELP rubin_node_peer_count Currently tracked peers.",
		"# TYPE rubin_node_peer_count gauge",
		fmt.Sprintf("rubin_node_peer_count %.0f", peerCount),
		"# HELP rubin_node_mempool_txs Number of transactions currently in the mempool.",
		"# TYPE rubin_node_mempool_txs gauge",
		fmt.Sprintf("rubin_node_mempool_txs %.0f", mempoolTxs),
		"# HELP rubin_node_rpc_requests_total Total HTTP RPC requests by route and status.",
		"# TYPE rubin_node_rpc_requests_total counter",
	)

	routeKeys := make([]string, 0, len(routeStatus))
	for key := range routeStatus {
		routeKeys = append(routeKeys, key)
	}
	sort.Strings(routeKeys)
	for _, key := range routeKeys {
		parts := strings.SplitN(key, "|", 2)
		route := parts[0]
		status := "0"
		if len(parts) == 2 {
			status = parts[1]
		}
		lines = append(lines,
			fmt.Sprintf(
				"rubin_node_rpc_requests_total{route=%q,status=%q} %d",
				route,
				status,
				routeStatus[key],
			),
		)
	}

	lines = append(lines,
		"# HELP rubin_node_submit_tx_total Total submit_tx outcomes by result label.",
		"# TYPE rubin_node_submit_tx_total counter",
	)
	submitKeys := make([]string, 0, len(submitByResult))
	for key := range submitByResult {
		submitKeys = append(submitKeys, key)
	}
	sort.Strings(submitKeys)
	for _, key := range submitKeys {
		lines = append(lines,
			fmt.Sprintf(
				"rubin_node_submit_tx_total{result=%q} %d",
				key,
				submitByResult[key],
			),
		)
	}
	return strings.Join(lines, "\n") + "\n"
}

func writeJSONResponse(state *devnetRPCState, route string, w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, `{"accepted":false,"error":"encode failed"}`, http.StatusInternalServerError)
		status = http.StatusInternalServerError
	}
	if state != nil && state.metrics != nil {
		state.metrics.note(route, status)
	}
}

func decodeHexPayload(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "0x")
	trimmed = strings.TrimPrefix(trimmed, "0X")
	if trimmed == "" {
		return nil, errors.New("tx_hex is required")
	}
	if len(trimmed)%2 != 0 {
		return nil, errors.New("tx_hex must be even-length hex")
	}
	return hex.DecodeString(trimmed)
}

func parseHex32Value(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := decodeHexPayload(value)
	if err != nil {
		return out, err
	}
	if len(raw) != len(out) {
		return out, fmt.Errorf("expected 32-byte hex, got %d bytes", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func tipFromBlockStore(blockStore *node.BlockStore) (uint64, [32]byte, bool, error) {
	if blockStore == nil {
		return 0, [32]byte{}, false, errors.New("blockstore unavailable")
	}
	return blockStore.Tip()
}

func classifySubmitErr(err error) (int, string) {
	if err == nil {
		return http.StatusOK, "accepted"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "already in mempool"), strings.Contains(msg, "double-spend conflict"):
		return http.StatusConflict, "conflict"
	case strings.Contains(msg, "mempool full"), strings.Contains(msg, "nil mempool"), strings.Contains(msg, "blockstore"), strings.Contains(msg, "chainstate"):
		return http.StatusServiceUnavailable, "unavailable"
	default:
		return http.StatusUnprocessableEntity, "rejected"
	}
}

func ensureJSONBodyEOF(dec *json.Decoder) error {
	if dec == nil {
		return errors.New("nil decoder")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func (s *devnetRPCState) now() uint64 {
	if s == nil || s.nowUnix == nil {
		return nowUnixU64()
	}
	return s.nowUnix()
}
