package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	// announceBlock is the P2P full-block announcement hook for locally
	// mined blocks. It is best-effort at the RPC boundary; process-level
	// devnet evidence must still prove peer adoption instead of treating
	// /mine_next success as network success.
	announceBlock func([]byte) error
	stderr        io.Writer
	nowUnix       func() uint64
	metrics       *rpcMetrics
	// rpcMut serializes mutating devnet RPC work (mempool admits + live mining)
	// so concurrent HTTP handlers cannot interleave chain/mempool updates.
	rpcMut sync.Mutex
	miner  *node.Miner // devnet live mining for POST /mine_next; nil disables the route
	// gate is the operator-visible readiness latch observed via GET
	// /ready. All transitions and reads go through a single
	// sync.Mutex inside the gate, AND every public read (IsReady)
	// observes the gate's stored shutdownCtx under that same mutex —
	// so a /ready request that arrives after the lifecycle context
	// has been canceled atomically stamps Shutdown and returns false,
	// independent of whether cmd/rubin-node main goroutine has yet
	// reached MarkShutdown. This closes the race class issue #1303
	// flagged: shutdown observed by the gate at the moment of the
	// readiness decision, not separately by main.
	gate *readinessGate
	// identity stores startup-provided chain identity for the
	// /chain_identity route. nil means SetIdentity has not been called
	// (e.g. a test fixture that does not exercise identity-dependent
	// routes), and the /chain_identity handler returns 503 in that
	// case. Multiple SetIdentity calls overwrite the previous value;
	// in production cmd/rubin-node main.go invokes SetIdentity once
	// during startup wiring.
	identity *chainIdentity
}

// chainIdentity is a snapshot of startup-wired chain identity. Fields
// flow into devnetRPCState through SetIdentity and feed the read-only
// /chain_identity route. The struct deliberately stores raw [32]byte
// values: hex encoding happens at the handler boundary so identity
// comparison stays a byte equality check, not a hex string compare.
type chainIdentity struct {
	network     string
	chainID     [32]byte
	genesisHash [32]byte
}

// readyStateNotReady, readyStateReady, readyStateShutdown encode the
// three states of the readiness gate. NotReady is the zero value so a
// freshly zeroed gate behaves correctly without explicit init.
const (
	readyStateNotReady int8 = 0
	readyStateReady    int8 = 1
	readyStateShutdown int8 = 2
)

// readinessGate serializes readiness state transitions and reads under
// a single mutex AND owns the lifecycle shutdown context so that every
// public decision observes shutdown atomically with the state read.
//
// Strict invariants:
//
//   - TryMarkReadyOnStartup transitions NotReady → Ready only when the
//     gate has not already been stamped Shutdown AND shutdownCtx has
//     not been canceled. If shutdownCtx is observed canceled, the gate
//     stamps Shutdown atomically before returning false — there is no
//     observable interleaving where Ready could be set after the
//     lifecycle context was already canceled.
//   - MarkShutdown stamps Shutdown unconditionally; idempotent.
//   - IsReady observes shutdownCtx under the same mutex; if it is
//     canceled at the moment of the read, the gate stamps Shutdown and
//     returns false. After Shutdown the gate never returns to Ready.
//
// shutdownCtx may be nil in tests that exercise the state primitive
// without a lifecycle context; with shutdownCtx == nil the gate
// behaves as a state-only latch (no auto-stamp on read).
//
// Acceptance reading (the claim this gate makes): startup-ready and
// shutdown-accepted transitions are serialized through one readiness
// gate; once the gate accepts shutdown — either via MarkShutdown or
// via observing the shutdownCtx canceled inside any public method —
// Ready cannot be re-entered for this gate's lifetime.
//
// Out-of-scope (explicit non-goal): the gate does NOT promise that no
// /ready handler invocation initiated before the lifecycle signal can
// complete its 200 response. A request already inside the handler
// when ctx becomes canceled completes its in-flight work; the
// guarantee is for the next public decision, not for already-running
// HTTP responses. Strict request-time arbitration would require a
// broader lifecycle/request owner outside this PR's scope.
type readinessGate struct {
	mu          sync.Mutex
	state       int8
	shutdownCtx context.Context
}

// newReadinessGate constructs a gate. For state-only fixtures that do
// not need cancellation, pass context.Background() or context.TODO()
// rather than nil so constructor callers follow normal context
// conventions. Reserve nil for explicit low-level tests that construct
// readinessGate directly and intentionally disable shutdown observation.
func newReadinessGate(shutdownCtx context.Context) *readinessGate {
	return &readinessGate{shutdownCtx: shutdownCtx}
}

// observeShutdownLocked stamps Shutdown if g.shutdownCtx is non-nil and
// has been canceled. Caller MUST hold g.mu. Returns true iff the gate
// is now (or was already) in Shutdown state.
func (g *readinessGate) observeShutdownLocked() bool {
	if g.state == readyStateShutdown {
		return true
	}
	if g.shutdownCtx == nil {
		return false
	}
	select {
	case <-g.shutdownCtx.Done():
		g.state = readyStateShutdown
		return true
	default:
		return false
	}
}

// TryMarkReadyOnStartup performs the boot-time NotReady → Ready
// transition under one lock. Returns true iff the gate was NotReady
// AND shutdownCtx was not canceled at the moment of the call AND the
// transition won. Returns false in every other case (already Ready,
// already Shutdown, or shutdownCtx observed canceled — in which case
// the gate is also stamped Shutdown before return). Nil-receiver
// safe.
func (g *readinessGate) TryMarkReadyOnStartup() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.observeShutdownLocked() {
		return false
	}
	if g.state != readyStateNotReady {
		return false
	}
	g.state = readyStateReady
	return true
}

// MarkShutdown stamps the gate into the sticky Shutdown state.
// Idempotent. Nil-receiver safe.
func (g *readinessGate) MarkShutdown() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state = readyStateShutdown
}

// IsReady returns true iff the gate is in Ready state AND shutdownCtx
// (if wired) has not been canceled at the moment of the call. If
// shutdownCtx is observed canceled, the gate is stamped Shutdown
// atomically before return so subsequent reads remain false.
// Nil-receiver safe.
func (g *readinessGate) IsReady() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.observeShutdownLocked() {
		return false
	}
	return g.state == readyStateReady
}

// setShutdownCtx is used at construction-adjacent wiring time to
// late-bind shutdownCtx after newDevnetRPCState. Caller MUST NOT hold
// g.mu when invoking this method.
func (g *readinessGate) setShutdownCtx(ctx context.Context) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.shutdownCtx = ctx
}

// TryMarkReadyOnStartup forwards to the gate. Nil-receiver safe.
func (s *devnetRPCState) TryMarkReadyOnStartup() bool {
	if s == nil {
		return false
	}
	return s.gate.TryMarkReadyOnStartup()
}

// MarkShutdown forwards to the gate. Nil-receiver safe.
func (s *devnetRPCState) MarkShutdown() {
	if s == nil {
		return
	}
	s.gate.MarkShutdown()
}

// IsReady forwards to the gate. The gate's IsReady observes shutdownCtx
// under its own mutex, so callers cannot accidentally bypass the
// shutdown observation by reading state directly. Nil-receiver safe.
func (s *devnetRPCState) IsReady() bool {
	if s == nil {
		return false
	}
	return s.gate.IsReady()
}

// SetShutdownCtx late-binds the lifecycle shutdown context onto the
// gate. cmd/rubin-node calls this once after newDevnetRPCState and
// before the first /ready handler can run.
func (s *devnetRPCState) SetShutdownCtx(ctx context.Context) {
	if s == nil {
		return
	}
	s.gate.setShutdownCtx(ctx)
}

// SetIdentity stores the provided identity values on the rpc state
// for the /chain_identity route to read. Subsequent calls overwrite
// the previous value (no single-assignment guard); cmd/rubin-node
// main.go invokes this once during startup wiring. Tests can call
// SetIdentity with arbitrary values to observe the resulting
// /chain_identity response, or leave state.identity nil to observe
// the 503 response. Nil-receiver safe.
func (s *devnetRPCState) SetIdentity(network string, chainID, genesisHash [32]byte) {
	if s == nil {
		return
	}
	s.identity = &chainIdentity{
		network:     network,
		chainID:     chainID,
		genesisHash: genesisHash,
	}
}

type runningDevnetRPCServer struct {
	addr   string
	server *http.Server
	state  *devnetRPCState
}

// TryMarkReadyOnStartup forwards through to the underlying gate.
// Returns true iff the gate transitioned NotReady → Ready under its
// internal lock with shutdownCtx live. Nil-receiver safe.
func (s *runningDevnetRPCServer) TryMarkReadyOnStartup() bool {
	if s == nil {
		return false
	}
	return s.state.TryMarkReadyOnStartup()
}

// MarkShutdown forwards the sticky shutdown stamp through to the gate.
// Nil-receiver safe.
func (s *runningDevnetRPCServer) MarkShutdown() {
	if s == nil {
		return
	}
	s.state.MarkShutdown()
}

// IsReady forwards through to the gate's locked IsReady, which
// observes shutdownCtx atomically with the state read. Nil-receiver
// safe.
func (s *runningDevnetRPCServer) IsReady() bool {
	if s == nil {
		return false
	}
	return s.state.IsReady()
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

type mineNextResponse struct {
	Mined     bool    `json:"mined"`
	Height    *uint64 `json:"height,omitempty"`
	BlockHash *string `json:"block_hash,omitempty"`
	Timestamp *uint64 `json:"timestamp,omitempty"`
	Nonce     *uint64 `json:"nonce,omitempty"`
	TxCount   *int    `json:"tx_count,omitempty"`
	Error     string  `json:"error,omitempty"`
}

type getMempoolResponse struct {
	Count int      `json:"count"`
	TxIDs []string `json:"txids"`
	Error string   `json:"error,omitempty"`
}

type getTxResponse struct {
	Found  bool    `json:"found"`
	TxID   string  `json:"txid,omitempty"`
	RawHex *string `json:"raw_hex,omitempty"`
	Error  string  `json:"error,omitempty"`
}

type txStatusResponse struct {
	Status string `json:"status"`
	TxID   string `json:"txid,omitempty"`
	Error  string `json:"error,omitempty"`
}

// chainIdentityResponse is the bounded read-only payload served by GET
// /chain_identity. All three fields are required (no omitempty) so
// the wire shape is stable for orchestrators that assert presence.
type chainIdentityResponse struct {
	Network        string `json:"network"`
	ChainIDHex     string `json:"chain_id_hex"`
	GenesisHashHex string `json:"genesis_hash_hex"`
}

// healthResponse is the bounded operator snapshot served by GET
// /health. ready reads the existing readiness gate (this PR does not
// redefine readiness/shutdown semantics). Height and TipHash are
// pointer-typed so they encode as JSON null when the local ChainState
// has no tip yet — has_tip distinguishes the two cases without
// conflating "no tip" with "RPC failure". The remaining fields are
// non-optional snapshots of existing node state; renaming or adding
// fields is out of scope for this PR.
type healthResponse struct {
	Ready           bool    `json:"ready"`
	HasTip          bool    `json:"has_tip"`
	Height          *uint64 `json:"height"`
	TipHash         *string `json:"tip_hash"`
	BestKnownHeight uint64  `json:"best_known_height"`
	InIBD           bool    `json:"in_ibd"`
	PeerCount       int     `json:"peer_count"`
	MempoolTxs      int     `json:"mempool_txs"`
	MempoolBytes    int     `json:"mempool_bytes"`
}

// peerEntry mirrors the bounded subset of node.PeerState plus the
// VersionPayloadV1 fields that an operator can act on. The handler
// must NOT add free-form fields beyond this struct so the operator
// surface stays bounded; out-of-scope additions belong in a new Q.
type peerEntry struct {
	Addr              string `json:"addr"`
	HandshakeComplete bool   `json:"handshake_complete"`
	BanScore          int    `json:"ban_score"`
	LastError         string `json:"last_error"`
	ProtocolVersion   uint32 `json:"protocol_version"`
	BestHeight        uint64 `json:"best_height"`
	TxRelay           bool   `json:"tx_relay"`
	PrunedBelowHeight uint64 `json:"pruned_below_height"`
	DaMempoolSize     uint32 `json:"da_mempool_size"`
}

// peersResponse is the bounded payload served by GET /peers. Count
// equals len(Peers) by construction in handlePeers, and Peers is
// sorted by Addr ascending for deterministic output across map
// iteration randomization.
type peersResponse struct {
	Count int         `json:"count"`
	Peers []peerEntry `json:"peers"`
}

func newDevnetRPCState(
	syncEngine *node.SyncEngine,
	blockStore *node.BlockStore,
	mempool *node.Mempool,
	peerManager *node.PeerManager,
	announceTx func([]byte) error,
	announceBlock func([]byte) error,
	stderr io.Writer,
	liveMiner *node.Miner,
) *devnetRPCState {
	if stderr == nil {
		stderr = io.Discard
	}
	return &devnetRPCState{
		syncEngine:    syncEngine,
		blockStore:    blockStore,
		mempool:       mempool,
		peerManager:   peerManager,
		announceTx:    announceTx,
		announceBlock: announceBlock,
		stderr:        stderr,
		nowUnix:       nowUnixU64,
		metrics:       newRPCMetrics(),
		miner:         liveMiner,
		// gate starts seeded with context.TODO() (never canceled) —
		// production wiring uses newDevnetRPCStateWithLifecycle below
		// to late-bind the actual lifecycle ctx. Tests that exercise
		// the readiness API call SetShutdownCtx explicitly; tests
		// that don't care leave the gate on the placeholder ctx and
		// observe state-only behavior (observeShutdownLocked's select
		// default branch returns false because TODO never cancels).
		gate: newReadinessGate(context.TODO()),
	}
}

// newDevnetRPCStateWithLifecycle is the canonical production wiring for
// a *devnetRPCState that participates in the cmd/rubin-node readiness
// lifecycle. It is the single function cmd/rubin-node uses to construct
// the state — combining newDevnetRPCState with state.SetShutdownCtx so
// the gate observes the actual lifecycle ctx instead of the placeholder
// context.TODO() from the bare constructor.
//
// Putting both steps inside one helper makes the wiring testable as a
// unit: tests that pre-cancel ctx and call this helper directly fail
// red if the helper internally drops the SetShutdownCtx call.
// cmd/rubin-node main.go calls THIS helper (not newDevnetRPCState +
// SetShutdownCtx separately) so the production wiring path matches
// the regression-test wiring path exactly.
func newDevnetRPCStateWithLifecycle(
	syncEngine *node.SyncEngine,
	blockStore *node.BlockStore,
	mempool *node.Mempool,
	peerManager *node.PeerManager,
	announceTx func([]byte) error,
	announceBlock func([]byte) error,
	stderr io.Writer,
	liveMiner *node.Miner,
	shutdownCtx context.Context,
) *devnetRPCState {
	// The bare newDevnetRPCState constructor intentionally does not
	// accept ctx — it is reused by tests that do not need a lifecycle
	// gate observation. The shutdownCtx is late-bound here via
	// SetShutdownCtx so the gate transitions from its placeholder
	// context.TODO() seed to the actual lifecycle ctx in a single
	// canonical wiring step. contextcheck is disabled for this line
	// because the ctx is not lost — it is forwarded to the gate via
	// SetShutdownCtx on the very next statement.
	//nolint:contextcheck
	state := newDevnetRPCState(syncEngine, blockStore, mempool, peerManager, announceTx, announceBlock, stderr, liveMiner)
	state.SetShutdownCtx(shutdownCtx)
	return state
}

// rpcBindHostIsLoopback reports whether the host part of host:port is suitable
// for devnet-only live mining RPC (loopback only). Non-loopback binds disable
// live mining even when network=devnet.
func rpcBindHostIsLoopback(bindAddr string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(bindAddr))
	if err != nil {
		return false
	}
	port = strings.TrimSpace(port)
	if port == "" {
		return false
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

// startDevnetRPCServer binds the devnet RPC listener and starts serving.
// Shutdown is driven exclusively by cmd/rubin-node/main.go's deferred
// rpcServer.Close(...) call; this function neither accepts nor observes
// a context — there used to be an inline `<-ctx.Done()` goroutine that
// called server.Shutdown in parallel with main.go's defer, but that
// produced two concurrent Shutdown calls on the same *http.Server. The
// defer in main.go is the single canonical Shutdown call site, so the
// readiness flag's "false-on-shutdown" hop runs at exactly one place.
func startDevnetRPCServer(
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
		// ReadTimeout bounds the total duration for reading the entire
		// request (headers + body) — it is NOT a body-only budget layered
		// on top of ReadHeaderTimeout. 10 s is ample for a 2 MiB body plus
		// normal-size headers and stops slow-loris body writes from pinning
		// a goroutine indefinitely.
		// WriteTimeout is deliberately NOT set: Go's WriteTimeout is a
		// request-scoped total-handler deadline, not a per-syscall socket
		// timeout like Rust's `set_write_timeout(5s)` in devnet_rpc.rs. A
		// hard WriteTimeout would abort long-running RPCs such as
		// /mine_next (PoW-bound) even when the client is reading promptly.
		// IdleTimeout keeps the connection pool bounded.
		ReadTimeout: 10 * time.Second,
		IdleTimeout: 60 * time.Second,
	}
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
	return &runningDevnetRPCServer{addr: addr, server: server, state: state}, nil
}

func (s *runningDevnetRPCServer) Close(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

// readyResponse is the tiny JSON payload served by GET /ready. The shape
// is intentionally minimal: a single boolean. Status code (200 vs 503) is
// the primary contract for orchestrators; the body is for human eyes.
type readyResponse struct {
	Ready bool `json:"ready"`
}

func handleReady(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/ready"
	if r.Method != http.MethodGet {
		// RFC 9110 §15.5.6 requires 405 responses to advertise the
		// permitted methods via an Allow response header so generic HTTP
		// clients and debugging tools can self-correct without re-reading
		// the body. Set the header BEFORE writeJSONResponse calls
		// WriteHeader because headers are frozen once status is written.
		w.Header().Set("Allow", http.MethodGet)
		// Match the JSON-error envelope used by the rest of the devnet
		// RPC surface (see handleGetTip / handleSubmitTx non-method paths
		// at L364+ / L511+) so /ready stays machine-readable on error.
		// Status stays 405 — semantically correct for method-not-allowed
		// and pinned by TestReadyHandlerRejectsNonGet.
		writeJSONResponse(state, route, w, http.StatusMethodNotAllowed, submitTxResponse{
			Accepted: false,
			Error:    "GET required",
		})
		return
	}
	if state.IsReady() {
		writeJSONResponse(state, route, w, http.StatusOK, readyResponse{Ready: true})
		return
	}
	writeJSONResponse(state, route, w, http.StatusServiceUnavailable, readyResponse{Ready: false})
}

func newDevnetRPCHandler(state *devnetRPCState) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		handleReady(state, w, r)
	})
	mux.HandleFunc("/get_tip", func(w http.ResponseWriter, r *http.Request) {
		handleGetTip(state, w, r)
	})
	mux.HandleFunc("/get_block", func(w http.ResponseWriter, r *http.Request) {
		handleGetBlock(state, w, r)
	})
	mux.HandleFunc("/submit_tx", func(w http.ResponseWriter, r *http.Request) {
		handleSubmitTx(state, w, r)
	})
	mux.HandleFunc("/mine_next", func(w http.ResponseWriter, r *http.Request) {
		handleMineNext(state, w, r)
	})
	mux.HandleFunc("/get_mempool", func(w http.ResponseWriter, r *http.Request) {
		handleGetMempool(state, w, r)
	})
	mux.HandleFunc("/get_tx", func(w http.ResponseWriter, r *http.Request) {
		handleGetTx(state, w, r)
	})
	mux.HandleFunc("/tx_status", func(w http.ResponseWriter, r *http.Request) {
		handleTxStatus(state, w, r)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		handleMetrics(state, w, r)
	})
	mux.HandleFunc("/chain_identity", func(w http.ResponseWriter, r *http.Request) {
		handleChainIdentity(state, w, r)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		handleHealth(state, w, r)
	})
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		handlePeers(state, w, r)
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
		// Canonical index resolved but underlying file is missing — storage error,
		// not "block not found".  Return 503 for Go/Rust parity.
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

	const maxBodyBytes = 2 << 20
	if r.ContentLength > maxBodyBytes {
		state.metrics.noteSubmit("bad_request")
		writeJSONResponse(state, route, w, http.StatusRequestEntityTooLarge, submitTxResponse{
			Accepted: false,
			Error:    "request body too large",
		})
		return
	}
	var req submitTxRequest
	// http.MaxBytesReader enforces maxBodyBytes for chunked / unknown-length
	// bodies as well. When the limit is exceeded the wrapped reader surfaces
	// a *http.MaxBytesError, which lets us return 413 instead of collapsing
	// an oversized body into a generic "invalid JSON body" 400.
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	// Defer the Close AFTER the MaxBytesReader wrap so the deferred call
	// targets the wrapped reader (any wrapper-specific Close behavior runs,
	// and the close aligns with what dec / drainSubmitTxBody actually read).
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		respondSubmitTxBodyError(state, route, w, err)
		return
	}
	if err := drainSubmitTxBody(dec, r.Body); err != nil {
		respondSubmitTxBodyError(state, route, w, err)
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
	state.rpcMut.Lock()
	admitErr := state.mempool.AddTx(raw)
	state.rpcMut.Unlock()
	if admitErr != nil {
		status, result := classifySubmitErr(admitErr)
		state.metrics.noteSubmit(result)
		writeJSONResponse(state, route, w, status, submitTxResponse{
			Accepted: false,
			Error:    admitErr.Error(),
		})
		return
	}
	// Announce runs outside rpcMut: it is p2p broadcast, not chain/mempool
	// mutation, so serializing with /mine_next under the rpc op lock would
	// block mine_next on a potentially slow network callback for no benefit.
	if state.announceTx != nil {
		if err := state.announceTx(raw); err != nil {
			_, _ = fmt.Fprintf(state.stderr, "rpc: announce-tx: %v\n", err)
		}
	}
	state.metrics.noteSubmit("accepted")
	writeJSONResponse(state, route, w, http.StatusOK, submitTxResponse{
		Accepted: true,
		TxID:     hex.EncodeToString(txid[:]),
	})
}

func handleMineNext(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/mine_next"
	if r.Method != http.MethodPost {
		writeJSONResponse(state, route, w, http.StatusBadRequest, mineNextResponse{
			Mined: false,
			Error: "POST required",
		})
		return
	}
	if state == nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, mineNextResponse{
			Mined: false,
			Error: "rpc unavailable",
		})
		return
	}
	if state.miner == nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, mineNextResponse{
			Mined: false,
			Error: "live mining unavailable",
		})
		return
	}
	state.rpcMut.Lock()
	mb, err := state.miner.MineOne(r.Context(), nil)
	if err != nil {
		state.rpcMut.Unlock()
		writeJSONResponse(state, route, w, http.StatusUnprocessableEntity, mineNextResponse{
			Mined: false,
			Error: err.Error(),
		})
		return
	}
	state.rpcMut.Unlock()
	if state.announceBlock != nil {
		if state.blockStore == nil {
			_, _ = fmt.Fprintf(state.stderr, "rpc: announce-block: block store unavailable for %x\n", mb.Hash)
		} else if blockBytes, err := state.blockStore.GetBlockByHash(mb.Hash); err != nil {
			_, _ = fmt.Fprintf(state.stderr, "rpc: announce-block: get mined block %x: %v\n", mb.Hash, err)
		} else if err := state.announceBlock(blockBytes); err != nil {
			_, _ = fmt.Fprintf(state.stderr, "rpc: announce-block: %v\n", err)
		}
	}
	height := mb.Height
	ts := mb.Timestamp
	nonce := mb.Nonce
	txCount := mb.TxCount
	hash := hex.EncodeToString(mb.Hash[:])
	writeJSONResponse(state, route, w, http.StatusOK, mineNextResponse{
		Mined:     true,
		Height:    &height,
		BlockHash: &hash,
		Timestamp: &ts,
		Nonce:     &nonce,
		TxCount:   &txCount,
	})
}

// parseTxIDQuery decodes a 64-hex-char "txid" query parameter into a [32]byte.
// Returns an error if the parameter is missing, has wrong length, or decodes
// to non-hex bytes.
func parseTxIDQuery(r *http.Request) ([32]byte, error) {
	var txid [32]byte
	raw := r.URL.Query().Get("txid")
	if raw == "" {
		return txid, fmt.Errorf("missing required query parameter: txid")
	}
	if len(raw) != 64 {
		return txid, fmt.Errorf("txid must be 64 hex characters (got %d)", len(raw))
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return txid, fmt.Errorf("txid is not valid hex: %w", err)
	}
	copy(txid[:], decoded)
	return txid, nil
}

func handleGetMempool(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/get_mempool"
	if r.Method != http.MethodGet {
		writeJSONResponse(state, route, w, http.StatusBadRequest, getMempoolResponse{
			Count: 0,
			TxIDs: []string{},
			Error: "GET required",
		})
		return
	}
	if state == nil || state.mempool == nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, getMempoolResponse{
			Count: 0,
			TxIDs: []string{},
			Error: "mempool unavailable",
		})
		return
	}
	ids := state.mempool.AllTxIDs()
	// Sort for deterministic response ordering (AllTxIDs order is not stable
	// because the underlying map iteration is randomized).
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	txids := make([]string, 0, len(ids))
	for _, id := range ids {
		txids = append(txids, hex.EncodeToString(id[:]))
	}
	writeJSONResponse(state, route, w, http.StatusOK, getMempoolResponse{
		Count: len(txids),
		TxIDs: txids,
	})
}

func handleGetTx(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/get_tx"
	if r.Method != http.MethodGet {
		writeJSONResponse(state, route, w, http.StatusBadRequest, getTxResponse{
			Found: false,
			Error: "GET required",
		})
		return
	}
	// Fail closed on mempool unavailability BEFORE parsing query parameters,
	// so an invalid/missing txid on an unavailable mempool still surfaces as
	// 503 (matching the contract shared by /get_block, /submit_tx, and other
	// handlers). Parsing first would mask unavailability behind a 400.
	if state == nil || state.mempool == nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, getTxResponse{
			Found: false,
			Error: "mempool unavailable",
		})
		return
	}
	txid, err := parseTxIDQuery(r)
	if err != nil {
		writeJSONResponse(state, route, w, http.StatusBadRequest, getTxResponse{
			Found: false,
			Error: err.Error(),
		})
		return
	}
	raw, ok := state.mempool.TxByID(txid)
	if !ok {
		writeJSONResponse(state, route, w, http.StatusOK, getTxResponse{
			Found: false,
			TxID:  hex.EncodeToString(txid[:]),
		})
		return
	}
	rawHex := hex.EncodeToString(raw)
	writeJSONResponse(state, route, w, http.StatusOK, getTxResponse{
		Found:  true,
		TxID:   hex.EncodeToString(txid[:]),
		RawHex: &rawHex,
	})
}

func handleTxStatus(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/tx_status"
	if r.Method != http.MethodGet {
		writeJSONResponse(state, route, w, http.StatusBadRequest, txStatusResponse{
			Status: "missing",
			Error:  "GET required",
		})
		return
	}
	// Fail closed on mempool unavailability BEFORE parsing query parameters
	// (matches handleGetTx and the contract of /get_block, /submit_tx).
	if state == nil || state.mempool == nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, txStatusResponse{
			Status: "missing",
			Error:  "mempool unavailable",
		})
		return
	}
	txid, err := parseTxIDQuery(r)
	if err != nil {
		writeJSONResponse(state, route, w, http.StatusBadRequest, txStatusResponse{
			Status: "missing",
			Error:  err.Error(),
		})
		return
	}
	status := "missing"
	if state.mempool.Contains(txid) {
		status = "pending"
	}
	writeJSONResponse(state, route, w, http.StatusOK, txStatusResponse{
		Status: status,
		TxID:   hex.EncodeToString(txid[:]),
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
		mempoolBytes    float64
		mempoolAdmit    node.MempoolAdmissionCounts
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
		// BytesUsed is a scrape-time read of the mempool's existing
		// usedBytes accounting (already maintained on every AddTx /
		// RemoveTx). AdmissionCounts is a snapshot of the per-outcome
		// counters that AddTx bumps at the final return path — read
		// here is purely a Load(), no increment, so rendering /metrics
		// repeatedly cannot perturb the counters.
		mempoolBytes = float64(state.mempool.BytesUsed())
		mempoolAdmit = state.mempool.AdmissionCounts()
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
		"# HELP rubin_node_mempool_bytes Raw byte size of transactions currently in the mempool.",
		"# TYPE rubin_node_mempool_bytes gauge",
		fmt.Sprintf("rubin_node_mempool_bytes %.0f", mempoolBytes),
		"# HELP rubin_node_mempool_admit_total Total mempool AddTx outcomes by result label.",
		"# TYPE rubin_node_mempool_admit_total counter",
		// Fixed rendering order: accepted, conflict, rejected,
		// unavailable. Buckets are the closed enum
		// MempoolAdmissionCounts; no free-form labels are emitted from
		// this surface.
		fmt.Sprintf(`rubin_node_mempool_admit_total{result="accepted"} %d`, mempoolAdmit.Accepted),
		fmt.Sprintf(`rubin_node_mempool_admit_total{result="conflict"} %d`, mempoolAdmit.Conflict),
		fmt.Sprintf(`rubin_node_mempool_admit_total{result="rejected"} %d`, mempoolAdmit.Rejected),
		fmt.Sprintf(`rubin_node_mempool_admit_total{result="unavailable"} %d`, mempoolAdmit.Unavailable),
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
	// Q-PV-13: parallel validation telemetry.
	if state != nil && state.syncEngine != nil {
		pvt := state.syncEngine.PVTelemetry()
		if pvt != nil {
			pvLines := pvt.Snapshot().PrometheusLines()
			lines = append(lines, pvLines...)
		}
	}

	return strings.Join(lines, "\n") + "\n"
}

func writeJSONResponse(state *devnetRPCState, route string, w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// Headers already sent — cannot change status code. Log the error
		// for observability; the client receives a truncated body.
		_, _ = fmt.Fprintf(w, `{"accepted":false,"error":"encode failed"}`)
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
	var txErr *node.TxAdmitError
	if errors.As(err, &txErr) {
		switch txErr.Kind {
		case node.TxAdmitConflict:
			return http.StatusConflict, "conflict"
		case node.TxAdmitUnavailable:
			return http.StatusServiceUnavailable, "unavailable"
		default:
			return http.StatusUnprocessableEntity, "rejected"
		}
	}
	// Defensive fallback for non-TxAdmitError (should not happen in normal flow).
	return http.StatusUnprocessableEntity, "rejected"
}

// drainSubmitTxBody finishes reading the /submit_tx body after the first JSON
// value has been decoded. It must distinguish three tail shapes:
//
//  1. Clean EOF (valid-only body) — return nil.
//  2. Non-whitespace trailing content within the cap — return a JSON-garbage
//     error so the caller returns 400.
//  3. Trailing content that exceeds maxBodyBytes — let http.MaxBytesReader
//     surface *http.MaxBytesError directly so the caller returns 413.
//
// The decoder's already-buffered tail and the underlying body reader are
// concatenated into a single stream via io.MultiReader and read through
// io.ReadAll. Every byte of the combined tail is then inspected for
// non-whitespace content, and http.MaxBytesReader surfaces
// *http.MaxBytesError from io.ReadAll when the combined tail exceeds the
// cap. This closes the "garbage past dec.Buffered()" class the earlier
// split-read implementation missed.
func drainSubmitTxBody(dec *json.Decoder, body io.Reader) error {
	if dec == nil {
		return errors.New("nil decoder")
	}
	// Scan BOTH the decoder's already-buffered tail and the rest of the
	// underlying body as a single stream. Reading through body (via
	// MultiReader → io.ReadAll) lets http.MaxBytesReader surface
	// *http.MaxBytesError for oversized tails while every byte in the
	// combined stream is inspected for non-whitespace garbage.
	tail, err := io.ReadAll(io.MultiReader(dec.Buffered(), body))
	if err != nil {
		return err
	}
	for _, b := range tail {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			return errors.New("unexpected trailing JSON value")
		}
	}
	return nil
}

func (s *devnetRPCState) now() uint64 {
	if s == nil || s.nowUnix == nil {
		return nowUnixU64()
	}
	return s.nowUnix()
}

// respondSubmitTxBodyError classifies a /submit_tx body-read / JSON-decode
// error into 413 "request body too large" when the http.MaxBytesReader cap
// was crossed and 400 "invalid JSON body" otherwise. Both the initial
// dec.Decode and the trailing drainSubmitTxBody check route through this
// helper so the oversize-vs-malformed distinction stays consistent on every
// path.
func respondSubmitTxBodyError(state *devnetRPCState, route string, w http.ResponseWriter, err error) {
	state.metrics.noteSubmit("bad_request")
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeJSONResponse(state, route, w, http.StatusRequestEntityTooLarge, submitTxResponse{
			Accepted: false,
			Error:    "request body too large",
		})
		return
	}
	writeJSONResponse(state, route, w, http.StatusBadRequest, submitTxResponse{
		Accepted: false,
		Error:    "invalid JSON body",
	})
}

// handleChainIdentity serves GET /chain_identity. It echoes the
// startup-wired chain identity so an operator can confirm which
// network/chain the running node belongs to without reading logs or
// /metrics. Identity flows from main.go startup wiring via
// SetIdentity; this handler does NOT independently choose devnet
// constants. Missing identity wiring fails closed with 503 instead of
// fabricating a devnet-shaped response. Non-GET methods return 405
// with an Allow: GET header (RFC 9110 §15.5.6) and the canonical JSON
// error envelope used by /ready.
func handleChainIdentity(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/chain_identity"
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONResponse(state, route, w, http.StatusMethodNotAllowed, submitTxResponse{
			Accepted: false,
			Error:    "GET required",
		})
		return
	}
	if state == nil || state.identity == nil || state.identity.network == "" {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
			Accepted: false,
			Error:    "chain identity unavailable",
		})
		return
	}
	writeJSONResponse(state, route, w, http.StatusOK, chainIdentityResponse{
		Network:        state.identity.network,
		ChainIDHex:     hex.EncodeToString(state.identity.chainID[:]),
		GenesisHashHex: hex.EncodeToString(state.identity.genesisHash[:]),
	})
}

// handleHealth serves GET /health, the bounded operator snapshot for
// orchestrators that need a single-call probe of liveness, tip state,
// peer count, and mempool fill without scraping /metrics or chasing
// individual routes. ready reads the existing readiness gate
// (state.IsReady — observed under the gate's mutex with shutdown
// atomically observed); this handler does NOT redefine readiness or
// shutdown semantics. ready=false from the gate is reported as a
// field on a 200 response, NOT as an HTTP failure: an orchestrator
// distinguishes "node up but not yet ready" (200 + ready:false) from
// "node missing required runtime state" (503). Missing BlockStore,
// PeerManager, Mempool, or SyncEngine fails closed with 503 rather
// than reporting fabricated zero counts.
func handleHealth(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/health"
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONResponse(state, route, w, http.StatusMethodNotAllowed, submitTxResponse{
			Accepted: false,
			Error:    "GET required",
		})
		return
	}
	if state == nil ||
		state.syncEngine == nil ||
		state.blockStore == nil ||
		state.peerManager == nil ||
		state.mempool == nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
			Accepted: false,
			Error:    "runtime dependency unavailable",
		})
		return
	}
	height, tipHash, hasTip, err := tipFromBlockStore(state.blockStore)
	if err != nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
			Accepted: false,
			Error:    err.Error(),
		})
		return
	}
	body := healthResponse{
		Ready:           state.IsReady(),
		HasTip:          hasTip,
		BestKnownHeight: state.syncEngine.BestKnownHeight(),
		InIBD:           state.syncEngine.IsInIBD(state.now()),
		PeerCount:       state.peerManager.Count(),
		MempoolTxs:      state.mempool.Len(),
		MempoolBytes:    state.mempool.BytesUsed(),
	}
	if hasTip {
		body.Height = &height
		tipHex := hex.EncodeToString(tipHash[:])
		body.TipHash = &tipHex
	}
	writeJSONResponse(state, route, w, http.StatusOK, body)
}

// handlePeers serves GET /peers, the deterministic snapshot of
// PeerManager.Snapshot() projected to a bounded JSON shape. Output
// MUST be sorted by Addr ascending so /peers responses are stable
// across map iteration randomization; map-iteration order would let
// two consecutive scrapes diff against each other for no semantic
// reason. Count equals len(Peers) by construction. Empty initialized
// peer set returns 200 with count:0 and peers:[] (NOT null). Nil
// PeerManager fails closed with 503; the handler never mutates peer
// state or accepts admin actions.
func handlePeers(state *devnetRPCState, w http.ResponseWriter, r *http.Request) {
	const route = "/peers"
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONResponse(state, route, w, http.StatusMethodNotAllowed, submitTxResponse{
			Accepted: false,
			Error:    "GET required",
		})
		return
	}
	if state == nil || state.peerManager == nil {
		writeJSONResponse(state, route, w, http.StatusServiceUnavailable, submitTxResponse{
			Accepted: false,
			Error:    "peer manager unavailable",
		})
		return
	}
	snapshot := state.peerManager.Snapshot()
	sort.Slice(snapshot, func(i, j int) bool { return snapshot[i].Addr < snapshot[j].Addr })
	peers := make([]peerEntry, 0, len(snapshot))
	for _, p := range snapshot {
		peers = append(peers, peerEntry{
			Addr:              p.Addr,
			HandshakeComplete: p.HandshakeComplete,
			BanScore:          p.BanScore,
			LastError:         p.LastError,
			ProtocolVersion:   p.RemoteVersion.ProtocolVersion,
			BestHeight:        p.RemoteVersion.BestHeight,
			TxRelay:           p.RemoteVersion.TxRelay,
			PrunedBelowHeight: p.RemoteVersion.PrunedBelowHeight,
			DaMempoolSize:     p.RemoteVersion.DaMempoolSize,
		})
	}
	writeJSONResponse(state, route, w, http.StatusOK, peersResponse{
		Count: len(peers),
		Peers: peers,
	})
}
