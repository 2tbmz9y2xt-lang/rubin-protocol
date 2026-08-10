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
		"requeue": func() { f.engine.requeueDisconnectedTransactions([][]byte{spentBlock}) },
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
		reorgTestCoinbaseForAddress(t, nextHeight, consensus.BlockSubsidyBig(nextHeight, live.alreadyGenerated.Big()), f.sourceAddress))
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
	engine.requeueDisconnectedTransactions([][]byte{rawBlock})
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

	engine.requeueDisconnectedTransactions([][]byte{{0xff, 0xfe}})
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
	engine.requeueDisconnectedTransactions([][]byte{rawBlock})

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
// engine locks were HELD at the moment the caller-supplied writer ran. It probes
// all six lock families named in the issue invariant — mutationMu, SyncEngine.mu,
// the ChainState admission guard, ChainState.mu, Mempool.mu and the
// PendingOutpointOwner mutex.
//
// It is itself safe for concurrent use, as SetStderr requires of any writer:
// flushes run outside mutationMu, so two mutations' flushes may overlap.
type diagnosticLockProbe struct {
	engine  *SyncEngine
	mempool *Mempool
	owner   *PendingOutpointOwner
	entered chan struct{}
	release chan struct{}

	mu            sync.Mutex
	buf           bytes.Buffer
	writes        int
	mutationHeld  bool
	stateHeld     bool
	admissionHeld bool
	chainHeld     bool
	mempoolHeld   bool
	ownerHeld     bool
}

// tryLock reports whether l was FREE, taking and releasing it when it was.
func tryLockFree(l interface {
	TryLock() bool
	Unlock()
},
) bool {
	if !l.TryLock() {
		return false
	}
	l.Unlock()
	return true
}

func (w *diagnosticLockProbe) Write(p []byte) (int, error) {
	// Measured BEFORE `entered` is published, so in the blocking phases the
	// sample is taken before any other goroutine can contend for these locks.
	mutationFree := tryLockFree(&w.engine.mutationMu)
	stateFree := tryLockFree(&w.engine.mu)
	admissionFree := tryLockFree(&w.engine.chainState.admissionMu)
	chainFree := tryLockFree(&w.engine.chainState.mu)
	mempoolFree, ownerFree := true, true
	if w.mempool != nil {
		mempoolFree = tryLockFree(&w.mempool.mu)
	}
	if w.owner != nil {
		ownerFree = tryLockFree(&w.owner.mu)
	}
	w.mu.Lock()
	w.writes++
	w.mutationHeld = w.mutationHeld || !mutationFree
	w.stateHeld = w.stateHeld || !stateFree
	w.admissionHeld = w.admissionHeld || !admissionFree
	w.chainHeld = w.chainHeld || !chainFree
	w.mempoolHeld = w.mempoolHeld || !mempoolFree
	w.ownerHeld = w.ownerHeld || !ownerFree
	w.mu.Unlock()
	if w.entered != nil {
		select {
		case w.entered <- struct{}{}:
		default:
		}
		<-w.release
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// held reports the six flags plus the write count under the probe's own mutex.
func (w *diagnosticLockProbe) held() (writes int, anyEngineLock bool, admission bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes, w.mutationHeld || w.stateHeld || w.chainHeld || w.mempoolHeld || w.ownerHeld, w.admissionHeld
}

func (w *diagnosticLockProbe) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return fmt.Sprintf("mutationMu=%v s.mu=%v admissionMu=%v ChainState.mu=%v Mempool.mu=%v owner.mu=%v",
		w.mutationHeld, w.stateHeld, w.admissionHeld, w.chainHeld, w.mempoolHeld, w.ownerHeld)
}

func (w *diagnosticLockProbe) output() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// TestSyncEngineDiagnosticWriterRunsAfterMutationUnlock pins the isolation
// contract on a public mutation entry point, in two phases.
//
// Phase 1 is single-goroutine, so a busy engine lock could only be this
// mutation's own: it proves every lock family the invariant names is free when
// the caller-supplied writer runs, and that the emitted bytes are unchanged. Its
// admission-guard claim is narrow — this path releases that guard inside
// bindMempoolUnderMutation before the flush, so the probe only catches a
// regression moving the flush back into that span; the load-bearing admission
// evidence is TestSyncEngineTransitionDiagnosticsFlushAfterUnlock, which drives
// the path that actually holds it.
//
// Phase 2 parks a writer inside Write and proves the liveness property the batch
// exists for: a SECOND canonical mutator acquires mutationMu and reaches its own
// result while the first call's writer is still blocked.
func TestSyncEngineDiagnosticWriterRunsAfterMutationUnlock(t *testing.T) {
	engine, chainState, blockStore := newDiagnosticEngine(t)
	bound, owner := boundPoolOf(engine)

	probe := &diagnosticLockProbe{engine: engine, mempool: bound, owner: owner}
	engine.SetStderr(probe)
	engine.SetMempool(newDiagnosticRejectionCandidate(t, chainState, blockStore))
	writes, engineLockHeld, admissionHeld := probe.held()
	if writes != 1 {
		t.Fatalf("writes=%d, want exactly one flushed record", writes)
	}
	if engineLockHeld || admissionHeld {
		t.Fatalf("locks held during writer I/O: %s", probe)
	}
	const want = "sync: mempool binding rejected, engine binding unchanged: mempool replacement is not supported after the initial binding\n"
	if got := probe.output(); got != want {
		t.Fatalf("emitted %q, want the unchanged diagnostic %q", got, want)
	}

	blocking := &diagnosticLockProbe{
		engine: engine, mempool: bound, owner: owner,
		entered: make(chan struct{}, 1), release: make(chan struct{}),
	}
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
	writes, engineLockHeld, admissionHeld = blocking.held()
	if engineLockHeld || admissionHeld {
		t.Fatalf("locks held while the writer blocked: %s", blocking)
	}
	// Make the phase-2 dependency explicit instead of implicit: the second
	// mutator is a tipless DisconnectTip, which produces NO diagnostic, so it
	// could not have blocked inside this same parked writer. If it ever starts
	// emitting, this fails rather than silently turning the liveness proof into
	// a second observation of the same blocked flush.
	if writes != 1 {
		t.Fatalf("writes=%d, want exactly the parked binding-rejection record; the second mutator must not emit", writes)
	}
	engine.SetStderr(io.Discard)
}

// boundPoolOf reads the engine's bound mempool and its owner the way production
// readers do, so a probe can name their locks.
func boundPoolOf(engine *SyncEngine) (*Mempool, *PendingOutpointOwner) {
	engine.mu.RLock()
	bound := engine.mempool
	engine.mu.RUnlock()
	return bound, bound.PendingOutpointOwner()
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

	// The terminal-latch record is NEVER evicted. This is the >=64-row reorg
	// with systematic PV-shadow mismatch: the batch is closed on both caps long
	// before the transition latches, and the one record an operator needs must
	// still arrive — after the truncation marker that accounts for the dropped
	// shadow noise.
	sink.Reset()
	latched := &diagnosticBatch{}
	for i := 0; i <= diagnosticBatchMaxRecords; i++ {
		engine.diagnose(latched, "pv_shadow: mismatch height=%d post_state_digest\n", i)
	}
	engine.diagnose(latched, "%s", strings.Repeat("z", diagnosticBatchMaxBytes)+"\n")
	engine.reportTerminalTransition(latched, "rollback restore failed", errors.New("probe cause"))
	if !latched.truncated || len(latched.records) != diagnosticBatchMaxRecords {
		t.Fatalf("closed batch: records=%d truncated=%v", len(latched.records), latched.truncated)
	}
	engine.flushDiagnostics(latched)
	const terminalRecord = "sync: canonical transition terminal (rollback restore failed), admission stays closed until restart: probe cause\n"
	out := sink.String()
	if !strings.HasSuffix(out, terminalRecord) {
		t.Fatalf("the closed batch dropped or reordered the terminal-latch record; flushed %d bytes ending %q", len(out), out[max(0, len(out)-120):])
	}
	if truncation := strings.Index(out, diagnosticBatchTruncatedRecord); truncation < 0 || truncation > strings.Index(out, terminalRecord) {
		t.Fatalf("want the truncation marker present and before the terminal record, got %q", out[max(0, len(out)-200):])
	}
}

// overlapWriter parks every Write until the test releases it, so the number of
// flushes simultaneously inside the writer is observable rather than inferred.
// It is safe for concurrent use, which is what SetStderr requires of a writer.
type overlapWriter struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	arrived chan struct{}
	release chan struct{}
}

func (w *overlapWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	w.arrived <- struct{}{}
	<-w.release
	return n, err
}

func (w *overlapWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// TestSyncEngineDiagnosticFlushesMayOverlapSafely pins the concurrency contract
// SetStderr states: because flushes run OUTSIDE mutationMu, several mutations'
// flush windows overlap by design. The test proves the overlap deterministically
// — it waits until every mutation's flush is parked inside the writer at the
// same time, which can only happen if each released mutationMu before flushing —
// and proves nothing is lost or garbled when they do. Under -race it is also the
// proof that the batches share no state.
func TestSyncEngineDiagnosticFlushesMayOverlapSafely(t *testing.T) {
	const mutations = 3
	engine, chainState, blockStore := newDiagnosticEngine(t)
	candidates := make([]*Mempool, 0, mutations)
	for i := 0; i < mutations; i++ {
		candidates = append(candidates, newDiagnosticRejectionCandidate(t, chainState, blockStore))
	}
	writer := &overlapWriter{arrived: make(chan struct{}, mutations), release: make(chan struct{})}
	engine.SetStderr(writer)

	var wg sync.WaitGroup
	for _, candidate := range candidates {
		wg.Add(1)
		go func(candidate *Mempool) {
			defer wg.Done()
			engine.SetMempool(candidate)
		}(candidate)
	}
	for parked := 0; parked < mutations; parked++ {
		select {
		case <-writer.arrived:
		case <-time.After(10 * time.Second):
			close(writer.release)
			wg.Wait()
			t.Fatalf("only %d of %d flushes were inside the writer at once; flushes are being serialized behind a lock", parked, mutations)
		}
	}
	close(writer.release)
	wg.Wait()
	if got := strings.Count(writer.String(), "sync: mempool binding rejected, engine binding unchanged: "); got != mutations {
		t.Fatalf("overlapping flushes delivered %d records, want %d intact", got, mutations)
	}
	engine.SetStderr(io.Discard)
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

	probe := &diagnosticLockProbe{engine: f.engine, mempool: f.mempool, owner: f.owner}
	f.engine.SetStderr(probe)
	if _, err := f.engine.ApplyBlock(f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, spend), nil); err == nil {
		t.Fatal("apply committed a block whose standard cleanup failed")
	}
	writes, engineLockHeld, admissionHeld := probe.held()
	if engineLockHeld {
		t.Fatalf("locks held during writer I/O: %s", probe)
	}
	if !admissionHeld {
		t.Fatal("the terminal latch released the admission guard; the fail-closed contract changed")
	}
	if writes != 2 {
		t.Fatalf("writes=%d, want the cleanup record and the terminal record", writes)
	}
	out := probe.output()
	cleanup := strings.Index(out, "sync: standard mempool cleanup failed at height ")
	terminal := strings.Index(out, "sync: canonical transition terminal (rollback restore failed), admission stays closed until restart: ")
	if cleanup < 0 || terminal < 0 || cleanup > terminal {
		t.Fatalf("emitted %q, want the unchanged cleanup record before the unchanged terminal record", out)
	}
	f.engine.SetStderr(io.Discard)
}

// flakySpendRotationProvider serves the real ML-DSA-87 spend suite for its first
// `full` queries and an empty set afterwards. A rotation provider that answers
// differently for the same height is exactly the divergence class PV shadow
// exists to catch, and it is reachable through public SyncConfig — no production
// seam is added to force it.
type flakySpendRotationProvider struct {
	mu    sync.Mutex
	calls int
	full  int
}

func (p *flakySpendRotationProvider) NativeCreateSuites(uint64) *consensus.NativeSuiteSet {
	return consensus.NewNativeSuiteSet(consensus.SUITE_ID_ML_DSA_87)
}

func (p *flakySpendRotationProvider) NativeSpendSuites(uint64) *consensus.NativeSuiteSet {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls <= p.full {
		return consensus.NewNativeSuiteSet(consensus.SUITE_ID_ML_DSA_87)
	}
	return consensus.NewNativeSuiteSet()
}

func (p *flakySpendRotationProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// TestSyncEnginePVShadowDiagnosticIsBatchedThroughApplyBlock drives a REAL PV
// shadow mismatch through the public ApplyBlock entry point, proving the PV
// producers' batch wiring (the diag literal they read as ctx.diag) end to end:
// dropping it fails this test, because the record would then be written from
// under mutationMu.
//
// The divergence is honest — the sequential connect consumes exactly one
// NativeSpendSuites answer (measured), the shadow asks a second time, and a
// provider answering differently for one height is the class PV shadow reports.
// RotationProvider is public SyncConfig, so no production seam is added.
func TestSyncEnginePVShadowDiagnosticIsBatchedThroughApplyBlock(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	f.engine.pvMode = pvModeShadow
	flaky := &flakySpendRotationProvider{full: 1}
	f.engine.cfg.RotationProvider = flaky
	spend := f.spend(t, 700, 1)
	block := f.blockIncluding(t, f.tipHash, f.tipHeight+1, f.alreadyGenerated, 202, spend)

	probe := &diagnosticLockProbe{engine: f.engine, mempool: f.mempool, owner: f.owner}
	f.engine.SetStderr(probe)
	if _, err := f.engine.ApplyBlock(block, nil); err != nil {
		t.Fatalf("ApplyBlock: %v, want the sequential connect to succeed", err)
	}
	if got := flaky.count(); got < 2 {
		t.Fatalf("NativeSpendSuites calls=%d, want the shadow's second query; the shadow never ran", got)
	}
	writes, engineLockHeld, admissionHeld := probe.held()
	if engineLockHeld || admissionHeld {
		t.Fatalf("locks held during writer I/O: %s", probe)
	}
	if writes != 1 {
		t.Fatalf("writes=%d, want exactly the flushed PV mismatch record", writes)
	}
	want := fmt.Sprintf("pv_shadow: mismatch height=%d seq_ok par_err=", f.tipHeight+1)
	if got := probe.output(); !strings.HasPrefix(got, want) {
		t.Fatalf("emitted %q, want the unchanged PV shadow record %q", got, want)
	}
	f.engine.SetStderr(io.Discard)
}

// TestSyncEngineRequeueDiagnosticIsBatchedThroughReorg drives a REAL requeue
// failure through the public ApplyBlockWithReorg entry point: the winning branch
// double-spends the outpoint of the block it displaces, so the displaced
// transaction cannot be readmitted. It is the end-to-end proof for the requeue
// producer's batch wiring — the diag literal applyPreferredBranch passes after
// the transition ends but while mutationMu is still held; dropping it fails this
// test.
func TestSyncEngineRequeueDiagnosticIsBatchedThroughReorg(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	forkHash, forkHeight, forkGenerated := f.tipHash, f.tipHeight+1, f.alreadyGenerated

	// Both spends are signed BEFORE either branch is applied: they consume the
	// same live outpoint, so the second could not be built once the first is on
	// chain — which is exactly why the requeue of the displaced one fails.
	displaced := f.spend(t, 700, 1)
	conflicting := f.spend(t, 600, 2)

	// Canonical branch A: one block spending the fixture's mature coinbase.
	if _, err := f.engine.ApplyBlock(f.blockIncluding(t, forkHash, forkHeight, forkGenerated, 202, displaced), nil); err != nil {
		t.Fatalf("ApplyBlock(A): %v", err)
	}

	// Competing branch B at the same height, spending the SAME outpoint with a
	// different amount, then one more block so B outweighs A.
	//
	// The probe is installed BEFORE B1: at equal height and work, fork choice
	// breaks the tie on the lexicographically lower tip hash, and the fixture's
	// block hashes come from freshly generated key material, so the switch lands
	// on B1 or on B2 depending on the run. Both orders disconnect A and requeue
	// its displaced transaction, so the assertions below hold either way — but
	// only if the writer is watching the whole sequence.
	probe := &diagnosticLockProbe{engine: f.engine, mempool: f.mempool, owner: f.owner}
	f.engine.SetStderr(probe)

	blockB1 := f.blockIncluding(t, forkHash, forkHeight, forkGenerated, 303, conflicting)
	if _, err := f.engine.ApplyBlockWithReorg(blockB1, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B1): %v", err)
	}
	hashB1, err := consensus.BlockHash(blockHeaderBytes(t, blockB1))
	if err != nil {
		t.Fatalf("BlockHash(B1): %v", err)
	}
	generatedB2 := forkGenerated + consensus.BlockSubsidy(forkHeight, forkGenerated)
	blockB2 := buildSingleTxBlock(t, hashB1, f.target, 304,
		reorgTestCoinbaseForAddress(t, forkHeight+1, consensus.BlockSubsidy(forkHeight+1, generatedB2), f.destAddress))
	hashB2, err := consensus.BlockHash(blockHeaderBytes(t, blockB2))
	if err != nil {
		t.Fatalf("BlockHash(B2): %v", err)
	}
	if _, err := f.engine.ApplyBlockWithReorg(blockB2, nil); err != nil {
		t.Fatalf("ApplyBlockWithReorg(B2): %v", err)
	}
	if got := f.engine.chainState.TipHash; got != hashB2 {
		t.Fatalf("tip=%x, want branch B's tip %x: nothing was disconnected or requeued", got, hashB2)
	}
	writes, engineLockHeld, admissionHeld := probe.held()
	if engineLockHeld || admissionHeld {
		t.Fatalf("locks held during writer I/O: %s", probe)
	}
	if writes == 0 {
		t.Fatal("the reorg produced no requeue diagnostic; the double spend was readmitted?")
	}
	if got := probe.output(); !strings.Contains(got, "mempool: requeue-tx: ") {
		t.Fatalf("emitted %q, want the unchanged requeue record", got)
	}
	f.engine.SetStderr(io.Discard)
}
