package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestSetStderrNil(t *testing.T) {
	engine := &SyncEngine{stderr: io.Discard}
	engine.SetStderr(nil)
	if engine.stderr != io.Discard {
		t.Fatal("SetStderr(nil) should fallback to io.Discard")
	}
}

func TestSetStderrOnNilEngine(t *testing.T) {
	var engine *SyncEngine
	engine.SetStderr(io.Discard) // must not panic
}

func TestSetStderrSetsWriter(t *testing.T) {
	var buf bytes.Buffer
	engine := &SyncEngine{stderr: io.Discard}
	engine.SetStderr(&buf)
	if engine.stderr != &buf {
		t.Fatal("SetStderr should set the provided writer")
	}
}

// lockProbeWriter records, from INSIDE Write, whether the engine's own mutex is
// free at the moment the diagnostic I/O runs. The engine's write lock is taken
// only if it is uncontended, and released immediately, so a successful TryLock
// is proof that diagnosticWriter released s.mu before handing the writer over —
// and a failed one, in this deliberately single-goroutine phase, is proof that
// it did not.
type lockProbeWriter struct {
	engine   *SyncEngine
	buf      bytes.Buffer
	writes   int
	lockHeld bool // set when the engine mutex was NOT free during a write
}

func (w *lockProbeWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.engine.mu.TryLock() {
		w.engine.mu.Unlock()
	} else {
		w.lockHeld = true
	}
	return w.buf.Write(p)
}

// lockedWriter is a concurrency-safe sink for the racing phase, where several
// producers and SetStderr run at once.
type lockedWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// stderrProducers returns every SyncEngine diagnostic producer reachable WITHOUT
// an open canonical transition, each driven the way production drives it.
//
// "binding rejection" runs through the public SetMempool entry point, so it
// exercises the BATCHED form: the record is retained and flushed after
// mutationMu is released. The others are driven directly with a nil batch, which
// is the direct form legal for a caller holding none of the engine's locks —
// exactly the position these calls are in. TestSyncEngineDiagnosticWriter*
// pin the batched isolation properties the direct form cannot show.
//
// One diagnostic site is deliberately absent: the standard-cleanup failure
// report in commitPreparedBlockUnderGuard, which only fires inside an open
// transition and would need that whole fixture here. It is exercised, together
// with the in-transition terminal report, by
// TestSyncEngineTransitionDiagnosticsFlushAfterUnlock — the repository
// call-site audit, not this list, is what proves no SyncEngine site reads
// s.stderr raw. Adding a transition-free diagnostic site without adding it here
// leaves it unproven.
func stderrProducers(t *testing.T, f *pendingOutpointSyncFixture, spentBlock []byte, pvBlock []byte, pvCtx canonicalBlockApplyContext) map[string]func() {
	t.Helper()
	// A target the candidate's header cannot match, so the shadow's parallel
	// connect fails and runPVShadowOnSuccess takes its parErr branch.
	badTargetCtx := pvCtx
	badTarget := f.target
	badTarget[31] ^= 0xff
	badTargetCtx.expectedTarget = &badTarget
	return map[string]func(){
		// Binding rejection: a different pointer after the initial binding.
		"binding rejection": func() { f.engine.SetMempool(f.newPool(t)) },
		// Terminal transition report: the fail-closed latch notice.
		"terminal transition": func() {
			f.engine.reportTerminalTransition(nil, "stderr probe", errors.New("probe cause"))
		},
		// Requeue diagnostic: the block's inputs are already spent on chain, so
		// readmission fails and the failure is reported.
		"requeue": func() { f.engine.requeueDisconnectedTransactions([][]byte{spentBlock}, nil) },
		// PV shadow, sequential-error branch: the parallel run of a VALID block
		// reports OK against the supplied sequential error, so the codes differ
		// and the mismatch line is emitted deterministically.
		"pv shadow seq error": func() {
			f.engine.runPVShadowOnError(pvBlock, nil, pvCtx, errors.New("probe sequential error"))
		},
		// PV shadow, sequential-success branches. Both are driven: the parallel
		// error branch through a target the block cannot match, and the
		// post-state-digest branch through a zero-digest sequential summary that
		// the real connected digest cannot equal.
		"pv shadow par error": func() {
			f.engine.runPVShadowOnSuccess(pvBlock, nil, badTargetCtx, &ChainStateConnectSummary{})
		},
		"pv shadow digest mismatch": func() {
			f.engine.runPVShadowOnSuccess(pvBlock, nil, pvCtx, &ChainStateConnectSummary{})
		},
	}
}

// TestSyncEngineStderrRaceAllProducers pins the diagnostic-writer contract on
// every SyncEngine producer reachable without an open canonical transition —
// binding rejection, terminal transition report, requeue, and all three PV
// shadow branches — at once: each reads the writer through the single
// synchronized helper, none holds a SyncEngine mutex across the writer I/O, the
// emitted bytes are unchanged, and racing SetStderr against all of them is clean
// under -race. See stderrProducers for the one site outside that reach and where
// it is covered instead.
//
// The lock probe is the part a race detector cannot give: -race proves the field
// read is synchronized, but a helper that held s.mu across an arbitrary
// caller-supplied writer would ALSO be race-clean while putting foreign,
// possibly blocking or re-entrant, code inside the engine's own mutex.
func TestSyncEngineStderrRaceAllProducers(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)

	// A block whose transaction is spent on chain: requeueing it fails.
	spend := f.spend(t, 700, 1)
	if err := f.mempool.AddTx(spend); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	spentBlock := f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, spend)
	summary, err := f.engine.ApplyBlock(spentBlock, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(including spend): %v", err)
	}

	// A next block that CONNECTS CLEANLY, plus the context a shadow run
	// consumes. Height and issuance are read from the live chainstate the shadow
	// clones, never recomputed here and never taken from the summary: the
	// summary's issuance field is not the "total issued before the next block"
	// term BlockSubsidy wants, and a subsidy off by that difference makes the
	// parallel connect fail — which would silently rob the post-state-digest
	// branch below of its only reachable path.
	live := f.engine.chainState.view()
	nextHeight := summary.BlockHeight + 1
	pvBlock := buildSingleTxBlock(t, summary.BlockHash, f.target, 303,
		reorgTestCoinbaseForAddress(t, nextHeight, consensus.BlockSubsidy(nextHeight, live.alreadyGenerated), f.sourceAddress))
	pvCtx := canonicalBlockApplyContext{
		blockHeight:    nextHeight,
		expectedTarget: &f.target,
		prevState:      cloneChainState(f.engine.chainState),
	}

	producers := stderrProducers(t, f, spentBlock, pvBlock, pvCtx)
	// The three PV lines share a prefix, so each wants the fragment that
	// identifies its own branch: a producer must not be able to pass by
	// emitting a sibling branch's line.
	wantContains := map[string]string{
		"binding rejection":         "sync: mempool binding rejected, engine binding unchanged: ",
		"terminal transition":       "sync: canonical transition terminal (stderr probe), admission stays closed until restart: ",
		"requeue":                   "mempool: requeue-tx: ",
		"pv shadow seq error":       "seq_err=ERR par_err=OK",
		"pv shadow par error":       "seq_ok par_err=BLOCK_ERR_TARGET_INVALID",
		"pv shadow digest mismatch": "post_state_digest",
	}

	// Phase 1 — single goroutine, so a busy engine mutex can only be this
	// producer's own. Also pins the emitted bytes.
	for name, produce := range producers {
		probe := &lockProbeWriter{engine: f.engine}
		f.engine.SetStderr(probe)
		produce()
		if probe.writes == 0 {
			t.Fatalf("%s: produced no diagnostic; the probe cannot prove anything", name)
		}
		if probe.lockHeld {
			t.Fatalf("%s: the engine mutex was held across the diagnostic writer I/O", name)
		}
		if got := probe.buf.String(); !strings.Contains(got, wantContains[name]) {
			t.Fatalf("%s: emitted %q, want the unchanged line containing %q", name, got, wantContains[name])
		}
	}

	// Phase 2 — every producer racing SetStderr. The rewiring CHURNS for the
	// producers' whole lifetime rather than firing a fixed burst: a burst can
	// drain before the slower producers reach their diagnostic, and then an
	// unsynchronized read has nothing to race against. Under -race this fails on
	// any diagnostic site that reads the writer field directly.
	sinks := []io.Writer{io.Discard, &lockedWriter{}, &lockedWriter{}}
	done := make(chan struct{})
	var churn sync.WaitGroup
	for w := 0; w < 2; w++ {
		churn.Add(1)
		go func(w int) {
			defer churn.Done()
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				f.engine.SetStderr(sinks[(i+w)%len(sinks)])
			}
		}(w)
	}
	var wg sync.WaitGroup
	for _, produce := range producers {
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(produce func()) {
				defer wg.Done()
				produce()
			}(produce)
		}
	}
	wg.Wait()
	close(done)
	churn.Wait()
	f.engine.SetStderr(io.Discard)
}

// TestRequeueDisconnectedNoErrorOnCoinbaseOnly verifies that
// requeueDisconnectedTransactions does not log errors for coinbase-only
// blocks (which have no user txs to requeue).
func TestRequeueDisconnectedNoErrorOnCoinbaseOnly(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	chainState := NewChainState()
	blockStore, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	syncCfg := DefaultSyncConfig(nil, [32]byte{}, chainStatePath)
	engine, err := NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := NewMempool(chainState, blockStore, [32]byte{})
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

	var stderrBuf bytes.Buffer
	engine.SetStderr(&stderrBuf)

	cfg := DefaultMinerConfig()
	miner, err := NewMiner(chainState, blockStore, engine, cfg)
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	mined, err := miner.MineN(context.Background(), 1, nil)
	if err != nil {
		t.Fatalf("MineN: %v", err)
	}
	if len(mined) == 0 {
		t.Fatal("expected at least one mined block")
	}

	// Get the raw block bytes from blockstore to feed into requeue.
	rawBlock, err := blockStore.GetBlockByHash(mined[0].Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash: %v", err)
	}

	stderrBuf.Reset()
	engine.requeueDisconnectedTransactions([][]byte{rawBlock}, nil)
	if stderrBuf.Len() != 0 {
		t.Fatalf("expected no errors for coinbase-only block, got: %s", stderrBuf.String())
	}
}

// TestRequeueDisconnectedSkipsUnparseableBlocks verifies that unparseable
// blocks are silently skipped (pre-existing behavior; parse error → continue).
func TestRequeueDisconnectedSkipsUnparseableBlocks(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	chainState := NewChainState()
	blockStore, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	syncCfg := DefaultSyncConfig(nil, [32]byte{}, chainStatePath)
	engine, err := NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := NewMempool(chainState, blockStore, [32]byte{})
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

	var stderrBuf bytes.Buffer
	engine.SetStderr(&stderrBuf)

	engine.requeueDisconnectedTransactions([][]byte{{0xff, 0xfe}}, nil)
	if stderrBuf.Len() != 0 {
		t.Fatalf("expected no stderr for unparseable block, got: %s", stderrBuf.String())
	}
}

// TestApplyBlockMempoolEvictStderrPlumbing verifies that the stderr field
// is correctly wired through the block-apply path and does not produce
// spurious errors for valid blocks.
func TestApplyBlockMempoolEvictStderrPlumbing(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	chainState := NewChainState()
	blockStore, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	syncCfg := DefaultSyncConfig(nil, [32]byte{}, chainStatePath)
	engine, err := NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := NewMempool(chainState, blockStore, [32]byte{})
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

	var stderrBuf bytes.Buffer
	engine.SetStderr(&stderrBuf)

	cfg := DefaultMinerConfig()
	miner, err := NewMiner(chainState, blockStore, engine, cfg)
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}

	// Mine a block — this calls ApplyBlock internally. Because the block is
	// valid, EvictConfirmed/RemoveConflicting should succeed and stderr
	// should remain empty.
	_, err = miner.MineN(context.Background(), 1, nil)
	if err != nil {
		t.Fatalf("MineN: %v", err)
	}
	output := stderrBuf.String()
	if strings.Contains(output, "mempool:") {
		t.Fatalf("expected no mempool errors for valid block, got: %s", output)
	}
}

// TestRequeueDisconnectedLogsAddTxError verifies that requeueDisconnectedTransactions
// writes an error to stderr when AddTx fails (e.g. inputs already spent).
func TestRequeueDisconnectedLogsAddTxError(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	chainState := NewChainState()
	blockStore, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	syncCfg := DefaultSyncConfig(nil, devnetGenesisChainID, chainStatePath)
	engine, err := NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := NewMempool(chainState, blockStore, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)

	var stderrBuf bytes.Buffer
	engine.SetStderr(&stderrBuf)

	// Mine 102 blocks so at least one coinbase UTXO is mature.
	// Genesis (height 0) has subsidy=0; height 1 has subsidy>0 and
	// CreationHeight=1. At height 101: 101-1=100 >= COINBASE_MATURITY.
	minerCfg := DefaultMinerConfig()
	minerCfg.MineAddress = fromAddress
	miner, err := NewMiner(chainState, blockStore, engine, minerCfg)
	if err != nil {
		t.Fatalf("NewMiner: %v", err)
	}
	if _, err := miner.MineN(context.Background(), 102, nil); err != nil {
		t.Fatalf("MineN(102): %v", err)
	}

	// Find a mature coinbase UTXO belonging to fromAddress.
	// Maturity check: nextHeight >= CreationHeight + COINBASE_MATURITY,
	// where nextHeight = chainState.Height + 1.
	nextHeight := chainState.Height + 1
	var spendOP consensus.Outpoint
	var spendEntry consensus.UtxoEntry
	found := false
	for op, entry := range chainState.Utxos {
		if entry.CreatedByCoinbase && entry.Value > 0 &&
			bytes.Equal(entry.CovenantData, fromAddress) &&
			nextHeight >= entry.CreationHeight+consensus.COINBASE_MATURITY {
			spendOP = op
			spendEntry = entry
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no mature coinbase UTXO found")
	}

	// Build a signed transfer tx spending the mature coinbase.
	txBytes := mustBuildSignedTransferTx(
		t,
		map[consensus.Outpoint]consensus.UtxoEntry{spendOP: spendEntry},
		[]consensus.Outpoint{spendOP},
		spendEntry.Value-1, // amount
		1,                  // fee
		1,                  // nonce (must be >= 1 for non-coinbase)
		fromKey,
		fromAddress,
		toAddress,
	)

	// Mine a block containing the tx.
	mined, err := miner.MineN(context.Background(), 1, [][]byte{txBytes})
	if err != nil {
		t.Fatalf("MineN(1,tx): %v", err)
	}
	if mined[0].TxCount < 2 {
		t.Fatalf("expected at least 2 txs (coinbase+transfer), got %d", mined[0].TxCount)
	}

	// Get the raw block bytes from the blockstore.
	rawBlock, err := blockStore.GetBlockByHash(mined[0].Hash)
	if err != nil {
		t.Fatalf("GetBlockByHash: %v", err)
	}

	// Requeue the disconnected block: the tx's inputs are already spent,
	// so AddTx fails and the error is logged to stderr.
	stderrBuf.Reset()
	engine.requeueDisconnectedTransactions([][]byte{rawBlock}, nil)

	output := stderrBuf.String()
	if !strings.Contains(output, "mempool: requeue-tx:") {
		t.Fatalf("expected 'mempool: requeue-tx:' in stderr, got: %q", output)
	}
}

// newDiagnosticEngine builds the smallest engine that can produce a diagnostic
// from a PUBLIC mutation entry point: with a mempool bound, any further
// SetMempool call is a rejection — the cheapest batched producer there is, and
// it needs no chain, no mined block and no key material.
func newDiagnosticEngine(t *testing.T) (*SyncEngine, *ChainState, *BlockStore) {
	t.Helper()
	dir := t.TempDir()
	chainState := NewChainState()
	blockStore, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	engine, err := NewSyncEngine(chainState, blockStore, DefaultSyncConfig(nil, [32]byte{}, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	mempool, err := NewMempool(chainState, blockStore, [32]byte{})
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	engine.SetMempool(mempool)
	return engine, chainState, blockStore
}

func newDiagnosticRejectionCandidate(t *testing.T, chainState *ChainState, blockStore *BlockStore) *Mempool {
	t.Helper()
	candidate, err := NewMempool(chainState, blockStore, [32]byte{})
	if err != nil {
		t.Fatalf("NewMempool(candidate): %v", err)
	}
	return candidate
}

// diagnosticLockProbe answers the question the race detector cannot: which
// engine locks were HELD at the moment the caller-supplied writer ran. Every
// TryLock happens before the writer publishes `entered`, so the measurement is
// taken before any other goroutine in the test can contend for those locks.
type diagnosticLockProbe struct {
	engine  *SyncEngine
	entered chan struct{}
	release chan struct{}

	buf           bytes.Buffer
	writes        int
	mutationHeld  bool
	stateHeld     bool
	admissionHeld bool
}

func (w *diagnosticLockProbe) Write(p []byte) (int, error) {
	w.writes++
	if w.engine.mutationMu.TryLock() {
		w.engine.mutationMu.Unlock()
	} else {
		w.mutationHeld = true
	}
	if w.engine.mu.TryLock() {
		w.engine.mu.Unlock()
	} else {
		w.stateHeld = true
	}
	if w.engine.chainState.admissionMu.TryLock() {
		w.engine.chainState.admissionMu.Unlock()
	} else {
		w.admissionHeld = true
	}
	if w.entered != nil {
		select {
		case w.entered <- struct{}{}:
		default:
		}
		<-w.release
	}
	return w.buf.Write(p)
}

// TestSyncEngineDiagnosticWriterRunsAfterMutationUnlock pins the isolation
// contract on a public mutation entry point, in two phases. Phase 1 is
// single-goroutine, so a busy engine lock could only be this mutation's own: it
// proves mutationMu, s.mu and the admission guard are ALL free when the
// caller-supplied writer runs, and that the emitted bytes are unchanged. Phase 2
// parks a writer inside Write and proves the liveness property the batch exists
// for: a SECOND canonical mutator acquires mutationMu and reaches its own result
// while the first call's writer is still blocked.
func TestSyncEngineDiagnosticWriterRunsAfterMutationUnlock(t *testing.T) {
	engine, chainState, blockStore := newDiagnosticEngine(t)

	probe := &diagnosticLockProbe{engine: engine}
	engine.SetStderr(probe)
	engine.SetMempool(newDiagnosticRejectionCandidate(t, chainState, blockStore))
	if probe.writes != 1 {
		t.Fatalf("writes=%d, want exactly one flushed record", probe.writes)
	}
	if probe.mutationHeld || probe.stateHeld || probe.admissionHeld {
		t.Fatalf("locks held during writer I/O: mutationMu=%v s.mu=%v admissionMu=%v",
			probe.mutationHeld, probe.stateHeld, probe.admissionHeld)
	}
	const want = "sync: mempool binding rejected, engine binding unchanged: mempool replacement is not supported after the initial binding\n"
	if got := probe.buf.String(); got != want {
		t.Fatalf("emitted %q, want the unchanged diagnostic %q", got, want)
	}

	blocking := &diagnosticLockProbe{engine: engine, entered: make(chan struct{}, 1), release: make(chan struct{})}
	engine.SetStderr(blocking)
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		engine.SetMempool(newDiagnosticRejectionCandidate(t, chainState, blockStore))
	}()
	select {
	case <-blocking.entered:
	case <-time.After(5 * time.Second):
		close(blocking.release)
		t.Fatal("timed out waiting for the diagnostic writer to be entered")
	}
	second := make(chan error, 1)
	go func() { _, err := engine.DisconnectTip(); second <- err }()
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		close(blocking.release)
		t.Fatal("a second canonical mutator could not acquire mutationMu while the diagnostic writer was blocked")
	}
	close(blocking.release)
	<-firstDone
	if blocking.mutationHeld || blocking.stateHeld || blocking.admissionHeld {
		t.Fatalf("locks held while the writer blocked: mutationMu=%v s.mu=%v admissionMu=%v",
			blocking.mutationHeld, blocking.stateHeld, blocking.admissionHeld)
	}
	engine.SetStderr(io.Discard)
}

// reentrantDiagnosticWriter calls back into non-diagnostic SyncEngine mutations
// from inside Write, which is legal precisely because the flush holds no engine
// lock. The one-shot guard bounds the depth; this test is about deadlock, not
// recursion.
type reentrantDiagnosticWriter struct {
	engine *SyncEngine
	bound  *Mempool
	buf    bytes.Buffer
	writes int
}

func (w *reentrantDiagnosticWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		w.engine.SetMempool(w.bound) // same pointer: settled, no rebinding, no diagnostic
		_, _ = w.engine.DisconnectTip()
	}
	return w.buf.Write(p)
}

// TestSyncEngineDiagnosticWriterReentryDoesNotDeadlock drives the case where the
// operator's writer re-enters the engine from inside Write: the flush runs with
// mutationMu released, so those mutations acquire it and return instead of
// self-deadlocking against the call that is emitting.
func TestSyncEngineDiagnosticWriterReentryDoesNotDeadlock(t *testing.T) {
	engine, chainState, blockStore := newDiagnosticEngine(t)
	engine.mu.RLock()
	bound := engine.mempool
	engine.mu.RUnlock()

	writer := &reentrantDiagnosticWriter{engine: engine, bound: bound}
	engine.SetStderr(writer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		engine.SetMempool(newDiagnosticRejectionCandidate(t, chainState, blockStore))
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("re-entrant diagnostic writer deadlocked the emitting mutation")
	}
	if writer.writes == 0 {
		t.Fatal("the re-entrant writer was never invoked")
	}
	if !strings.Contains(writer.buf.String(), "sync: mempool binding rejected") {
		t.Fatalf("emitted %q, want the unchanged binding-rejection diagnostic", writer.buf.String())
	}
	engine.mu.RLock()
	stillBound := engine.mempool
	engine.mu.RUnlock()
	if stillBound != bound {
		t.Fatal("a re-entrant writer changed the engine's mempool binding")
	}
	engine.SetStderr(io.Discard)
}

// TestSyncEngineDiagnosticBatchBounded pins both caps at their exact boundary,
// the one-over behavior, the single fixed truncation record, below-cap byte and
// order fidelity, and flush-exactly-once.
func TestSyncEngineDiagnosticBatchBounded(t *testing.T) {
	var sink bytes.Buffer
	engine := &SyncEngine{stderr: &sink}

	records := &diagnosticBatch{}
	var want strings.Builder
	for i := 0; i < diagnosticBatchMaxRecords; i++ {
		engine.diagnose(records, "diagnostic record %d\n", i)
		fmt.Fprintf(&want, "diagnostic record %d\n", i)
	}
	if len(records.records) != diagnosticBatchMaxRecords || records.truncated {
		t.Fatalf("at the record cap: records=%d truncated=%v", len(records.records), records.truncated)
	}
	engine.diagnose(records, "one over the record cap\n")
	if !records.truncated || len(records.records) != diagnosticBatchMaxRecords {
		t.Fatalf("one over the record cap: records=%d truncated=%v", len(records.records), records.truncated)
	}
	want.WriteString(diagnosticBatchTruncatedRecord)
	engine.flushDiagnostics(records)
	if got := sink.String(); got != want.String() {
		t.Fatalf("flushed %q, want the below-cap records in producer order plus one truncation record %q", got, want.String())
	}
	sink.Reset()
	engine.flushDiagnostics(records)
	if sink.Len() != 0 {
		t.Fatalf("second flush emitted %q, want nothing", sink.String())
	}

	// Byte cap: a record that exactly fills the budget is retained; the next
	// one is dropped even though it is tiny.
	sink.Reset()
	full := strings.Repeat("x", diagnosticBatchMaxBytes-1) + "\n"
	bytesBatch := &diagnosticBatch{}
	engine.diagnose(bytesBatch, "%s", full)
	if bytesBatch.truncated || bytesBatch.bytes != diagnosticBatchMaxBytes {
		t.Fatalf("at the byte cap: bytes=%d truncated=%v", bytesBatch.bytes, bytesBatch.truncated)
	}
	engine.diagnose(bytesBatch, "one over the byte cap\n")
	if !bytesBatch.truncated || len(bytesBatch.records) != 1 {
		t.Fatalf("one over the byte cap: records=%d truncated=%v", len(bytesBatch.records), bytesBatch.truncated)
	}
	engine.flushDiagnostics(bytesBatch)
	if got, expected := sink.String(), full+diagnosticBatchTruncatedRecord; got != expected {
		t.Fatalf("byte-cap flush emitted %d bytes, want %d", len(got), len(expected))
	}

	// A record larger than the remaining budget is dropped whole and closes the
	// batch, so a later small record cannot jump ahead of it in the output.
	sink.Reset()
	oversized := &diagnosticBatch{}
	engine.diagnose(oversized, "first\n")
	engine.diagnose(oversized, "%s", strings.Repeat("y", diagnosticBatchMaxBytes)+"\n")
	engine.diagnose(oversized, "later small record\n")
	if !oversized.truncated || len(oversized.records) != 1 || oversized.bytes != len("first\n") {
		t.Fatalf("oversized record: records=%d bytes=%d truncated=%v", len(oversized.records), oversized.bytes, oversized.truncated)
	}
	engine.flushDiagnostics(oversized)
	if got, expected := sink.String(), "first\n"+diagnosticBatchTruncatedRecord; got != expected {
		t.Fatalf("oversized flush emitted %q, want %q", got, expected)
	}
}

// TestSyncEngineTransitionDiagnosticsFlushAfterUnlock covers the two producers
// that fire ONLY under an open canonical transition — the standard-cleanup
// failure and the terminal-latch report — driven through the public ApplyBlock
// entry point. Both records reach the writer unchanged and in producer order,
// with mutationMu and s.mu free.
//
// admissionMu is deliberately asserted as STILL HELD: this scenario ends in the
// terminal fail-closed latch, which retains the admission guard until the node
// restarts (canonicalTransition.end). That retention is pre-existing behavior
// this issue does not change, and it is harmless here because no mutation path
// re-acquires that guard after the latch — every entry point fails closed
// through mutationAllowed first. The assertion is exact so that any future
// change to the latch shows up here rather than silently.
func TestSyncEngineTransitionDiagnosticsFlushAfterUnlock(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	spend := f.spend(t, 700, 1)
	if err := f.mempool.AddTx(spend); err != nil {
		t.Fatalf("AddTx(spend): %v", err)
	}
	f.breakResidentClaim(t, txID(t, spend))

	probe := &diagnosticLockProbe{engine: f.engine}
	f.engine.SetStderr(probe)
	if _, err := f.engine.ApplyBlock(f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, spend), nil); err == nil {
		t.Fatal("apply committed a block whose standard cleanup failed")
	}
	if probe.mutationHeld || probe.stateHeld {
		t.Fatalf("locks held during writer I/O: mutationMu=%v s.mu=%v", probe.mutationHeld, probe.stateHeld)
	}
	if !probe.admissionHeld {
		t.Fatal("the terminal latch released the admission guard; the fail-closed contract changed")
	}
	if probe.writes != 2 {
		t.Fatalf("writes=%d, want the cleanup record and the terminal record", probe.writes)
	}
	out := probe.buf.String()
	cleanup := strings.Index(out, "sync: standard mempool cleanup failed at height ")
	terminal := strings.Index(out, "sync: canonical transition terminal (rollback restore failed), admission stays closed until restart: ")
	if cleanup < 0 || terminal < 0 || cleanup > terminal {
		t.Fatalf("emitted %q, want the unchanged cleanup record before the unchanged terminal record", out)
	}
	f.engine.SetStderr(io.Discard)
}
