package node

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// installMempoolImageForTest installs snapshot into m through the restore
// primitives buildMempoolRestoreMaps, PendingOutpointOwner.buildRestoreLocked,
// validateRestoredClaimBinding and PendingOutpointOwner.publishRestoreLocked, so
// the entry, accounting, high-water and claim-binding rules these tests assert
// are production rules.
//
// Two things are NOT production, and the tests below must not be read as proving
// them. The composition is test-local: production reaches these rules from
// prepareCanonicalMempoolPlan, which additionally requires the live image to
// equal the snapshot, while these tests deliberately install a foreign image.
// And buildRestoreLocked itself has no production caller — the canonical plan
// builder constructs its owner candidate with buildCanonicalOwnerIndex, which
// applies the same claim rules off-lock; only publishRestoreLocked and
// validateRestoredClaimBinding are on the production path.
func installMempoolImageForTest(m *Mempool, snapshot mempoolSnapshot) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.maxTxs <= 0 || m.maxBytes <= 0 {
		return fmt.Errorf("invalid mempool snapshot restore limits: max_txs=%d max_bytes=%d", m.maxTxs, m.maxBytes)
	}
	txs, wtxids, maxAdmissionSeq, usedBytes, err := buildMempoolRestoreMaps(snapshot.entries, m.maxTxs, m.maxBytes)
	if err != nil {
		return err
	}
	if snapshot.lastAdmissionSeq < maxAdmissionSeq {
		return fmt.Errorf("mempool snapshot admission high-watermark below restored max: last=%d max=%d", snapshot.lastAdmissionSeq, maxAdmissionSeq)
	}
	owner := m.pendingOutpointOwnerLocked()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	candidate, err := owner.buildRestoreLocked(snapshot.pending)
	if err != nil {
		return err
	}
	if err := validateRestoredClaimBinding(txs, candidate); err != nil {
		return err
	}
	owner.publishRestoreLocked(snapshot.pending, candidate)
	m.txs = txs
	m.wtxids = wtxids
	m.usedBytes = usedBytes
	m.lastAdmissionSeq = snapshot.lastAdmissionSeq
	m.currentMinFeeRate = snapshot.currentMinFeeRate
	m.ensureMinFeeRateLocked()
	return nil
}

type canonicalMOFixture struct {
	engine  *SyncEngine
	store   *BlockStore
	target  [32]byte
	mp      *Mempool
	signer  *consensus.MLDSA87Keypair
	address []byte
	ops     []consensus.Outpoint
	now     uint64
}

func mustCanonicalMO(t *testing.T, label string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
}

func awaitCanonicalMOError(t *testing.T, ch <-chan error, label string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatalf("%s did not finish", label)
		return nil
	}
}

func awaitCanonicalMOAdmissionRLock(t *testing.T, caller string) {
	t.Helper()
	deadline, stack := time.Now().Add(time.Second), make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		for _, goroutine := range strings.Split(string(stack[:runtime.Stack(stack, true)]), "\n\n") {
			atRLock := strings.Contains(goroutine, "sync.(*RWMutex).RLock") || strings.Contains(goroutine, "sync.runtime_SemacquireRWMutexR")
			if atRLock && strings.Contains(goroutine, caller) {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("%s did not block at admissionMu.RLock", caller)
}

func newCanonicalMOFixture(t *testing.T, inputs int, cfg MempoolConfig) *canonicalMOFixture {
	engine, store, target := newReorgTestEngine(t)
	signer, err := consensus.NewMLDSA87Keypair()
	mustCanonicalMO(t, "NewMLDSA87Keypair", err)
	t.Cleanup(signer.Close)
	f := &canonicalMOFixture{engine: engine, store: store, target: target, signer: signer, address: consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes()), now: 300}
	engine.chainState.mu.Lock()
	for i := 0; i < inputs; i++ {
		var txid [32]byte
		txid[0], txid[31] = byte(0xc0+i), byte(i+1)
		op := consensus.Outpoint{Txid: txid, Vout: 0}
		engine.chainState.Utxos[op] = consensus.UtxoEntry{Value: 1_000_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...), CreationHeight: 0}
		f.ops = append(f.ops, op)
	}
	engine.chainState.mu.Unlock()
	mp, err := NewMempoolWithConfig(engine.chainState, store, devnetGenesisChainID, cfg)
	mustCanonicalMO(t, "NewMempoolWithConfig", err)
	engine.SetMempool(mp)
	if engine.mempool != mp {
		t.Fatal("mempool did not bind")
	}
	f.mp = mp
	return f
}

func (f *canonicalMOFixture) raw(t *testing.T, op consensus.Outpoint, nonce uint64, core bool) []byte {
	return f.rawWithLocktime(t, op, nonce, core, 0)
}

func (f *canonicalMOFixture) rawWithLocktime(t *testing.T, op consensus.Outpoint, nonce uint64, core bool, locktime uint32) []byte {
	outputs := []consensus.TxOutput{{Value: 900_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...)}}
	if core {
		data := make([]byte, 33)
		outputs = []consensus.TxOutput{
			{Value: 1, CovenantType: consensus.COV_TYPE_CORE_SIMPLICITY, CovenantData: data},
			{Value: 899_999, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...)},
		}
	}
	tx := &consensus.Tx{Version: 1, TxKind: 0, TxNonce: nonce, Inputs: []consensus.TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout}}, Outputs: outputs, Locktime: locktime}
	mustCanonicalMO(t, "SignTransaction", consensus.SignTransaction(tx, f.engine.chainState.Utxos, devnetGenesisChainID, f.signer))
	raw, err := consensus.MarshalTx(tx)
	mustCanonicalMO(t, "MarshalTx", err)
	return raw
}

func (f *canonicalMOFixture) add(t *testing.T, op consensus.Outpoint, nonce uint64) [32]byte {
	raw := f.raw(t, op, nonce, false)
	mustCanonicalMO(t, "AddTx", f.mp.AddTx(raw))
	return txID(t, raw)
}

func (f *canonicalMOFixture) install(t *testing.T, op consensus.Outpoint, nonce uint64, core bool) [32]byte {
	return f.installRaw(t, f.raw(t, op, nonce, core))
}

func (f *canonicalMOFixture) installRaw(t *testing.T, raw []byte) [32]byte {
	tx, txid, wtxid, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	mustCanonicalMO(t, "TxWeightAndStats", err)
	owner := f.mp.PendingOutpointOwner()
	ctx, ok := owner.AdmissionContext()
	if !ok {
		t.Fatal("owner unavailable before manual entry")
	}
	token, err := owner.Reserve(ctx, PendingOutpointStandardMempool, txid, relayMetadataInputs(tx))
	mustCanonicalMO(t, "Reserve", err)
	mustCanonicalMO(t, "Finalize", owner.Finalize(token))
	f.mp.mu.Lock()
	f.mp.lastAdmissionSeq++
	entry := &mempoolEntry{raw: append([]byte(nil), raw...), txid: txid, wtxid: wtxid, inputs: relayMetadataInputs(tx), token: token, fee: consensus.Uint128FromU64(100_000), weight: weight, size: len(raw), admissionSeq: f.mp.lastAdmissionSeq, source: mempoolTxSourceLocal}
	f.mp.txs[txid], f.mp.wtxids[wtxid] = entry, txid
	f.mp.usedBytes += entry.size
	f.mp.mu.Unlock()
	return txid
}

func (f *canonicalMOFixture) applyCoinbase(t *testing.T) error {
	height := f.engine.chainState.Height + 1
	subsidy := consensus.BlockSubsidyBig(height, f.engine.chainState.AlreadyGenerated.Big())
	block := buildSingleTxBlock(t, f.engine.chainState.TipHash, f.target, reorgTestTimestamp(f.now), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy))
	f.now++
	_, err := f.engine.ApplyBlock(block, nil)
	return err
}

func (f *canonicalMOFixture) applySpend(t *testing.T, op consensus.Outpoint, nonce uint64) error {
	raw := f.raw(t, op, nonce, false)
	_, _, wtxid, _, err := consensus.ParseTx(raw)
	mustCanonicalMO(t, "ParseTx(spend)", err)
	height := f.engine.chainState.Height + 1
	subsidy := consensus.BlockSubsidyBig(height, f.engine.chainState.AlreadyGenerated.Big())
	block := buildMultiTxBlock(t, f.engine.chainState.TipHash, f.target, reorgTestTimestamp(f.now), coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t, height, subsidy+100_000, [][32]byte{{}, wtxid}), raw)
	f.now++
	_, err = f.engine.ApplyBlock(block, nil)
	return err
}

type canonicalMOProvider struct {
	mu                          sync.Mutex
	create, spend, deployments  int
	createHeights, spendHeights []uint64
	descriptors                 []consensus.SimplicityDeploymentDescriptor
	anchor                      [32]byte
	ok                          bool
	err                         error
	volatile                    bool
	createSet, spendSet         *consensus.NativeSuiteSet
	entered, release            chan struct{}
}

func newCanonicalMOProvider(t *testing.T, chainID [32]byte) *canonicalMOProvider {
	descriptors := []consensus.SimplicityDeploymentDescriptor{consensus.LiveSimplicityDeploymentDescriptor(chainID)}
	anchor, err := consensus.SimplicityDeploymentSetAnchor(chainID, descriptors)
	mustCanonicalMO(t, "SimplicityDeploymentSetAnchor", err)
	return &canonicalMOProvider{descriptors: descriptors, anchor: anchor, ok: true}
}

func (p *canonicalMOProvider) NativeCreateSuites(height uint64) *consensus.NativeSuiteSet {
	p.mu.Lock()
	p.create, p.createHeights = p.create+1, append(p.createHeights, height)
	call, volatile := p.create, p.volatile
	p.mu.Unlock()
	if volatile && call > 1 {
		return consensus.NewNativeSuiteSet()
	}
	if p.createSet != nil {
		return p.createSet.Clone()
	}
	return consensus.DefaultRotationProvider{}.NativeCreateSuites(height)
}

func (p *canonicalMOProvider) NativeSpendSuites(height uint64) *consensus.NativeSuiteSet {
	p.mu.Lock()
	p.spend, p.spendHeights = p.spend+1, append(p.spendHeights, height)
	call, volatile := p.spend, p.volatile
	p.mu.Unlock()
	if volatile && call > 1 {
		return consensus.NewNativeSuiteSet()
	}
	if p.spendSet != nil {
		return p.spendSet.Clone()
	}
	return consensus.DefaultRotationProvider{}.NativeSpendSuites(height)
}

func (p *canonicalMOProvider) PublishedSimplicityDeployments() ([]consensus.SimplicityDeploymentDescriptor, [32]byte, bool, error) {
	p.mu.Lock()
	p.deployments++
	descriptors, anchor, ok, err, entered, release, call, volatile := append([]consensus.SimplicityDeploymentDescriptor(nil), p.descriptors...), p.anchor, p.ok, p.err, p.entered, p.release, p.deployments, p.volatile
	p.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	if volatile && call > 1 {
		return nil, [32]byte{}, false, nil
	}
	return descriptors, anchor, ok, err
}

func (p *canonicalMOProvider) counts() (int, int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.create, p.spend, p.deployments
}

func assertCanonicalMOPlanAbort(t *testing.T, f *canonicalMOFixture) error {
	before, beforeView := canonicalMOImageFingerprint(t, f.mp, 0), f.engine.chainState.view()
	beforeIndex, err := f.store.CanonicalIndexSnapshot()
	mustCanonicalMO(t, "CanonicalIndexSnapshot(before)", err)
	writes := 0
	write := writeFileAtomicFn
	defer func() { writeFileAtomicFn = write }()
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		writes++
		return write(path, data, mode)
	}
	err = f.applyCoinbase(t)
	afterIndex, indexErr := f.store.CanonicalIndexSnapshot()
	if err == nil || indexErr != nil || writes != 0 || before != canonicalMOImageFingerprint(t, f.mp, 1) || f.engine.chainState.view() != beforeView || !reflect.DeepEqual(beforeIndex, afterIndex) || f.engine.persistenceFaulted() {
		t.Fatalf("plan abort err=%v indexErr=%v writes=%d latch=%v", err, indexErr, writes, f.engine.persistenceFaulted())
	}
	if _, ok := f.mp.PendingOutpointOwner().AdmissionContext(); !ok {
		t.Fatal("provider plan abort left admission closed")
	}
	return err
}

func TestCanonicalMOPlanDirectAndBootstrap(t *testing.T) {
	f := newCanonicalMOFixture(t, 1, MempoolConfig{})
	txid := f.add(t, f.ops[0], 1)
	mustCanonicalMO(t, "ApplyBlock", f.applySpend(t, f.ops[0], 2))
	if f.mp.Contains(txid) {
		t.Fatal("direct final-C1-invalid record survived")
	}
	dir := t.TempDir()
	store, err := CreateBlockStore(BlockStorePath(dir))
	mustCanonicalMO(t, "CreateBlockStore", err)
	engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(nil, devnetGenesisChainID, ChainStatePath(dir)))
	mustCanonicalMO(t, "NewSyncEngine", err)
	mp, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
	mustCanonicalMO(t, "NewMempool", err)
	engine.SetMempool(mp)
	mp.SetCurrentMinFeeRateForTest(8)
	before, ok := mp.PendingOutpointOwner().AdmissionContext()
	if !ok {
		t.Fatal("bootstrap owner unavailable before transition")
	}
	if err := engine.BootstrapCanonicalGenesisIfEmpty(); err != nil || !engine.chainState.HasTip || mp.Len() != 0 {
		t.Fatalf("BootstrapCanonicalGenesisIfEmpty: err=%v tip=%v pool=%d", err, engine.chainState.HasTip, mp.Len())
	}
	after, ok := mp.PendingOutpointOwner().AdmissionContext()
	if !ok || mp.CurrentMinFeeRateSnapshot() != 4 || after.Generation != before.Generation+1 || after.StableTip.Height != 0 {
		t.Fatalf("bootstrap M/O plan floor=%d before=%+v after=%+v", mp.CurrentMinFeeRateSnapshot(), before, after)
	}
	t.Run("terminal_snapshot_is_not_race_tolerant", func(t *testing.T) {
		terminal := fmt.Errorf("wrapped: %w", terminalCanonicalMempoolError(errors.New("test terminal")))
		if !errors.Is(raceTolerantBootstrapResult(terminal, true), terminal) || !errors.Is(raceTolerantBootstrapResult(errStoragePersistenceFault, true), errStoragePersistenceFault) {
			t.Fatal("bootstrap race helper hid a terminal result behind a tip")
		}
		dir := t.TempDir()
		store, err := CreateBlockStore(BlockStorePath(dir))
		mustCanonicalMO(t, "CreateBlockStore", err)
		engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(nil, devnetGenesisChainID, ChainStatePath(dir)))
		mustCanonicalMO(t, "NewSyncEngine", err)
		mp, err := NewMempool(engine.chainState, store, devnetGenesisChainID)
		mustCanonicalMO(t, "NewMempool", err)
		engine.SetMempool(mp)
		owner := mp.PendingOutpointOwner()
		owner.mu.Lock()
		owner.byToken[PendingOutpointToken{owner: owner, seq: 1}] = nil
		owner.mu.Unlock()
		if _, snapshotErr := snapshotMempool(mp); !isCanonicalMOTerminalError(snapshotErr) {
			t.Fatalf("snapshotMempool(nil claim) err=%v", snapshotErr)
		}
		err = engine.BootstrapCanonicalGenesisIfEmpty()
		if !isCanonicalMOTerminalError(err) || !engine.persistenceFaulted() || engine.chainState.HasTip {
			t.Fatalf("BootstrapCanonicalGenesisIfEmpty err=%v latch=%v tip=%v", err, engine.persistenceFaulted(), engine.chainState.HasTip)
		}
		if _, ok := owner.AdmissionContext(); ok {
			t.Fatal("nil owner claim terminal reopened admission")
		}
	})
}

func TestCanonicalMOPlanWinningReorg(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	forkHash, forkHeight, forkGenerated := f.tipHash, f.tipHeight, f.alreadyGenerated
	canonical := f.applyForkBlock(t)
	spend := f.spend(t, 700, 2)
	mustCanonicalMO(t, "AddTx(reorg record)", f.mempool.AddTx(spend))
	f.mempool.mu.Lock()
	f.mempool.lowWaterBytes = f.mempool.usedBytes
	f.mempool.mu.Unlock()
	f.mempool.SetCurrentMinFeeRateForTest(8)
	before, ok := f.owner.AdmissionContext()
	if !ok {
		t.Fatal("owner unavailable before reorg")
	}
	subsidyB1 := consensus.BlockSubsidy(forkHeight+1, forkGenerated)
	b1 := buildSingleTxBlock(t, forkHash, f.target, 203, reorgTestCoinbaseForAddress(t, forkHeight+1, subsidyB1, f.destAddress))
	b1Parsed, b1Hash := mustParseReorgBlockForTest(t, b1)
	if len(b1Parsed.Txs) != 1 {
		t.Fatal("row B1 must leave the ancestor resident input unspent")
	}
	mustCanonicalMO(t, "StoreBlock(B1)", f.store.StoreBlock(b1Hash, b1Parsed.HeaderBytes, b1))
	b2 := f.blockIncluding(t, b1Hash, forkHeight+2, forkGenerated+subsidyB1, 204, spend)
	_, err := f.engine.ApplyBlockWithReorg(b2, nil)
	mustCanonicalMO(t, "ApplyBlockWithReorg", err)
	after, ok := f.owner.AdmissionContext()
	if f.engine.chainState.TipHash == canonical.BlockHash || f.mempool.Contains(txID(t, spend)) || f.mempool.CurrentMinFeeRateSnapshot() != 2 || !ok || after.Generation != before.Generation+1 {
		t.Fatal("winning reorg retained the old-chain standard record")
	}
}

func TestCanonicalMOPlanStandaloneDisconnect(t *testing.T) {
	f := newCanonicalMOFixture(t, 2, MempoolConfig{})
	retained := f.add(t, f.ops[0], 1)
	included := f.raw(t, f.ops[1], 2, false)
	_, includedID, includedWTxID, _, err := consensus.ParseTx(included)
	mustCanonicalMO(t, "ParseTx(included)", err)
	height := f.engine.chainState.Height + 1
	subsidy := consensus.BlockSubsidyBig(height, f.engine.chainState.AlreadyGenerated.Big())
	block := buildMultiTxBlock(t, f.engine.chainState.TipHash, f.target, reorgTestTimestamp(f.now), coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t, height, subsidy+100_000, [][32]byte{{}, includedWTxID}), included)
	f.now++
	_, err = f.engine.ApplyBlock(block, nil)
	mustCanonicalMO(t, "ApplyBlock", err)
	removedRaw := mustBuildSignedTransferTxForSyncTest(t, f.engine.chainState.Utxos, []consensus.Outpoint{{Txid: includedID, Vout: 0}}, 700_000, 100_000, 3, f.signer, f.address, f.address)
	mustCanonicalMO(t, "AddTx(disconnect record)", f.mp.AddTx(removedRaw))
	removed := txID(t, removedRaw)
	f.mp.SetCurrentMinFeeRateForTest(8)
	_, err = f.engine.DisconnectTip()
	mustCanonicalMO(t, "DisconnectTip", err)
	if f.mp.Contains(removed) || !f.mp.Contains(retained) || f.mp.CurrentMinFeeRateSnapshot() != 8 {
		t.Fatalf("standalone final-C1 selection removed=%v retained=%v floor=%d", f.mp.Contains(removed), f.mp.Contains(retained), f.mp.CurrentMinFeeRateSnapshot())
	}
}

func TestCanonicalMOPlanFinalChainValidity(t *testing.T) {
	lock := newCanonicalMOFixture(t, 2, MempoolConfig{})
	boundaryRaw, lockedRaw := lock.rawWithLocktime(t, lock.ops[0], 1, false, uint32(lock.engine.chainState.Height+2)), lock.rawWithLocktime(t, lock.ops[1], 2, false, uint32(lock.engine.chainState.Height+3))
	boundary, locked := txID(t, boundaryRaw), txID(t, lockedRaw)
	_, _, boundaryWTxID, _, err := consensus.ParseTx(boundaryRaw)
	mustCanonicalMO(t, "ParseTx(locktime boundary)", err)
	_, _, lockedWTxID, _, err := consensus.ParseTx(lockedRaw)
	mustCanonicalMO(t, "ParseTx(locktime over)", err)
	mustCanonicalMO(t, "AddTx(locktime boundary)", lock.mp.AddTx(boundaryRaw))
	mustCanonicalMO(t, "AddTx(locktime over)", lock.mp.AddTx(lockedRaw))
	lock.mp.sigCache.Reset()
	if err := lock.applyCoinbase(t); err != nil || !lock.mp.Contains(boundary) || lock.mp.Contains(locked) {
		t.Fatalf("final-height locktime err=%v boundary=%v over=%v", err, lock.mp.Contains(boundary), lock.mp.Contains(locked))
	}
	lock.mp.mu.RLock()
	gotBoundary, keptBoundary := lock.mp.wtxids[boundaryWTxID]
	_, keptLocked := lock.mp.wtxids[lockedWTxID]
	wtxidCount, usedBytes := len(lock.mp.wtxids), lock.mp.usedBytes
	lock.mp.mu.RUnlock()
	if !keptBoundary || gotBoundary != boundary || keptLocked || wtxidCount != 1 || usedBytes != len(boundaryRaw) {
		t.Fatalf("publisher wtxids retained=%x/%v excluded=%v count=%d used=%d", gotBoundary, keptBoundary, keptLocked, wtxidCount, usedBytes)
	}
	emptyFinal, err := canonicalMempoolFinalStateOf(lock.engine.chainState, 0, nil)
	mustCanonicalMO(t, "canonicalMempoolFinalStateOf(empty)", err)
	selectedFinal, err := canonicalMempoolFinalStateOf(lock.engine.chainState, 0, []consensus.Outpoint{lock.ops[0]})
	mustCanonicalMO(t, "canonicalMempoolFinalStateOf(selected)", err)
	if len(emptyFinal.utxos) != 0 || len(selectedFinal.utxos) != 1 {
		t.Fatalf("bounded final UTXOs empty=%d selected=%d", len(emptyFinal.utxos), len(selectedFinal.utxos))
	}
	mtp := newCanonicalMOFixture(t, 0, MempoolConfig{})
	mustCanonicalMO(t, "ApplyBlock(MTP predecessor)", mtp.applyCoinbase(t))
	oldMTP, err := mtp.mp.nextBlockMTP(mtp.engine.chainState.Height + 1)
	mustCanonicalMO(t, "nextBlockMTP", err)
	maturity := reorgTestTimestamp(300)
	if oldMTP >= maturity {
		t.Fatalf("old MTP=%d, want below refund maturity %d", oldMTP, maturity)
	}
	refund := mustReorgMLDSA87Keypair(t)
	refundKeyID, claimKeyID := sha3.Sum256(refund.PubkeyBytes()), sha3.Sum256([]byte("canonical-mtp-claim"))
	var htlcTxid [32]byte
	htlcTxid[0] = 0xe1
	htlcOp := consensus.Outpoint{Txid: htlcTxid}
	htlcData := append(make([]byte, 32), consensus.LOCK_MODE_TIMESTAMP)
	htlcData = consensus.AppendU64le(htlcData, maturity)
	htlcData = append(htlcData, claimKeyID[:]...)
	htlcData = append(htlcData, refundKeyID[:]...)
	mtp.engine.chainState.mu.Lock()
	mtp.engine.chainState.Utxos[htlcOp] = consensus.UtxoEntry{Value: 1_000_000, CovenantType: consensus.COV_TYPE_HTLC, CovenantData: htlcData}
	mtp.engine.chainState.mu.Unlock()
	tx := &consensus.Tx{Version: 1, TxKind: 0, TxNonce: 9, Inputs: []consensus.TxInput{{PrevTxid: htlcOp.Txid, PrevVout: htlcOp.Vout}}, Outputs: []consensus.TxOutput{{Value: 900_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), mtp.address...)}}}
	digest, err := consensus.SighashV1DigestWithType(tx, 0, 1_000_000, devnetGenesisChainID, consensus.SIGHASH_ALL)
	mustCanonicalMO(t, "SighashV1DigestWithType", err)
	sig, err := refund.SignDigest32(digest)
	mustCanonicalMO(t, "SignDigest32", err)
	tx.Witness = []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL, Pubkey: refundKeyID[:], Signature: []byte{1}}, {SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: refund.PubkeyBytes(), Signature: append(sig, consensus.SIGHASH_ALL)}}
	htlcRaw := mustMarshalTxForNodeTest(t, tx)
	htlc := mtp.installRaw(t, htlcRaw)
	if err := mtp.applyCoinbase(t); err != nil || !mtp.mp.Contains(htlc) {
		t.Fatalf("final-MTP refund err=%v retained=%v", err, mtp.mp.Contains(htlc))
	}
	one := newCanonicalMOFixture(t, 1, MempoolConfig{})
	one.add(t, one.ops[0], 1)
	one.mp.sigCache.Reset()
	mustCanonicalMO(t, "ApplyBlock(single lower seam)", one.applyCoinbase(t))
	if hits, misses := one.mp.sigCache.Hits(), one.mp.sigCache.Misses(); hits != 0 || misses != 1 {
		t.Fatalf("lower seam cache hits=%d misses=%d, want 0/1", hits, misses)
	}
}

func TestCanonicalMOPlanPreservesPoolLocalPolicyAndHighWater(t *testing.T) {
	f := newCanonicalMOFixture(t, 1, MempoolConfig{MaxTransactions: 1})
	txid := f.add(t, f.ops[0], 1)
	beforeEntry, beforeClaim := residentClaim(t, f.mp, txid)
	f.mp.mu.Lock()
	f.mp.currentMinFeeRate = 1 << 40
	f.mp.txs[txid].source = mempoolTxSourceRemote
	beforeSeq := f.mp.lastAdmissionSeq
	f.mp.mu.Unlock()
	mustCanonicalMO(t, "ApplyBlock", f.applyCoinbase(t))
	f.mp.mu.RLock()
	floor, seq := f.mp.currentMinFeeRate, f.mp.lastAdmissionSeq
	f.mp.mu.RUnlock()
	afterEntry, afterClaim := residentClaim(t, f.mp, txid)
	if !f.mp.Contains(txid) || seq != beforeSeq || floor != 1<<39 || afterEntry.source != mempoolTxSourceRemote || afterEntry.token != beforeEntry.token || afterClaim == nil || beforeClaim == nil || afterClaim.token != beforeClaim.token {
		t.Fatalf("pool-local state changed: retained=%v seq=%d/%d floor=%d entry=%+v claim=%+v", f.mp.Contains(txid), seq, beforeSeq, floor, afterEntry, afterClaim)
	}
}

func TestCanonicalMOPlanOwnerClaimsAndDIndependence(t *testing.T) {
	f := newCanonicalMOFixture(t, 3, MempoolConfig{})
	standard := f.add(t, f.ops[0], 1)
	retained := f.add(t, f.ops[1], 2)
	retainedEntry, retainedClaim := residentClaim(t, f.mp, retained)
	owner := f.mp.PendingOutpointOwner()
	ctx, ok := owner.AdmissionContext()
	if !ok {
		t.Fatal("owner unavailable")
	}
	daToken, err := owner.Reserve(ctx, PendingOutpointDA, [32]byte{0xda}, []consensus.Outpoint{f.ops[2]})
	if err != nil || owner.Finalize(daToken) != nil {
		t.Fatalf("DA claim: token=%+v err=%v", daToken, err)
	}
	owner.mu.Lock()
	daBefore, daRowBefore := *owner.byToken[daToken], owner.byOutpoint[f.ops[2]]
	owner.mu.Unlock()
	before := owner.snapshot()
	beforeImage := canonicalMOImageFingerprint(t, f.mp, 0)
	mustCanonicalMO(t, "ApplyBlock", f.applySpend(t, f.ops[0], 2))
	after := owner.snapshot()
	entry, claim := residentClaim(t, f.mp, retained)
	if beforeImage == canonicalMOImageFingerprint(t, f.mp, 1) || f.mp.Contains(standard) || !f.mp.Contains(retained) || entry.token != retainedEntry.token || claim == nil || retainedClaim == nil || claim.token != retainedClaim.token || len(after.claims) != 2 || after.tokenHighWater != before.tokenHighWater || after.generationHighWater != before.generationHighWater+1 {
		t.Fatalf("owner image after standard exclusion=%+v image=%s", after, canonicalMOImageFingerprint(t, f.mp, 1))
	}
	var keptDA bool
	for _, item := range after.claims {
		keptDA = keptDA || item.token == daToken && item.domain == PendingOutpointDA
	}
	owner.mu.Lock()
	daAfter, daRowAfter := owner.byToken[daToken], owner.byOutpoint[f.ops[2]]
	owner.mu.Unlock()
	if !keptDA || daAfter == nil || !reflect.DeepEqual(daBefore, *daAfter) || daRowBefore != daRowAfter {
		t.Fatalf("DA claim/index changed before=%+v/%+v after=%+v/%+v", daBefore, daRowBefore, daAfter, daRowAfter)
	}
	if got, ok := owner.txidForOutpoint(f.ops[1]); !ok || got != retained {
		t.Fatalf("retained standard index=%x/%v want %x", got, ok, retained)
	}
}

func TestCanonicalMOPlanProviderSnapshotAndFirstErrorOrder(t *testing.T) {
	if canonicalMempoolValidationAbortsPlan(&consensus.TxError{Code: consensus.TX_ERR_SIMPLICITY_REJECTED}) {
		t.Fatal("unspecified_simplicity_disposition_family_excludes")
	}
	var typedNil *consensus.TxError
	if !canonicalMempoolValidationAbortsPlan(typedNil) || !canonicalMempoolValidationAbortsPlan(fmt.Errorf("wrapped: %w", &consensus.TxError{Code: consensus.TX_ERR_SIG_INVALID})) {
		t.Fatal("only a direct nonnil TxError may exclude")
	}
	if !canonicalMempoolCauseAbortsPlan(consensus.TxErrorCause(255)) {
		t.Fatal("unknown nonzero cause did not abort")
	}
	if !canonicalMempoolValidationAbortsPlan(errors.New("direct provider error")) {
		t.Fatal("non-TxError direct disposition did not abort")
	}
	heightProvider := newCanonicalMOProvider(t, devnetGenesisChainID)
	heightCache := newCanonicalMempoolRotationCache(heightProvider)
	heightCache.NativeCreateSuites(10)
	heightCache.NativeCreateSuites(11)
	heightCache.NativeCreateSuites(10)
	heightCache.NativeSpendSuites(20)
	heightCache.NativeSpendSuites(21)
	heightCache.NativeSpendSuites(20)
	heightProvider.mu.Lock()
	createHeights, spendHeights := append([]uint64(nil), heightProvider.createHeights...), append([]uint64(nil), heightProvider.spendHeights...)
	heightProvider.mu.Unlock()
	if create, spend, deployments := heightProvider.counts(); create != 2 || spend != 2 || deployments != 0 || !reflect.DeepEqual(createHeights, []uint64{10, 11}) || !reflect.DeepEqual(spendHeights, []uint64{20, 21}) {
		t.Fatalf("height-key observations create=%d/%v spend=%d/%v deployments=%d", create, createHeights, spend, spendHeights, deployments)
	}
	provider := newCanonicalMOProvider(t, devnetGenesisChainID)
	provider.volatile = true
	f := newCanonicalMOFixture(t, 2, MempoolConfig{RotationProvider: provider})
	first, second := f.install(t, f.ops[0], 1, true), f.install(t, f.ops[1], 2, true)
	mustCanonicalMO(t, "ApplyBlock", f.applyCoinbase(t))
	if create, spend, deployments := provider.counts(); create != 1 || spend != 1 || deployments != 1 || !f.mp.Contains(first) || !f.mp.Contains(second) {
		t.Fatalf("provider observations create=%d spend=%d deployments=%d first=%v second=%v", create, spend, deployments, f.mp.Contains(first), f.mp.Contains(second))
	}
	for _, row := range []struct {
		name string
		cfg  func(*canonicalMOProvider) MempoolConfig
		raw  func(*canonicalMOFixture) []byte
	}{
		{"native_create_rotation", func(p *canonicalMOProvider) MempoolConfig {
			p.createSet = consensus.NewNativeSuiteSet()
			return MempoolConfig{RotationProvider: p}
		}, func(f *canonicalMOFixture) []byte { return f.raw(t, f.ops[0], 1, false) }},
		{"native_spend_rotation", func(p *canonicalMOProvider) MempoolConfig {
			p.spendSet = consensus.NewNativeSuiteSet()
			return MempoolConfig{RotationProvider: p}
		}, func(f *canonicalMOFixture) []byte { return f.raw(t, f.ops[0], 1, false) }},
		{"unsupported_suite", func(p *canonicalMOProvider) MempoolConfig { return MempoolConfig{RotationProvider: p} }, func(f *canonicalMOFixture) []byte {
			return rewriteSyncTestWitnessSuiteID(t, f.raw(t, f.ops[0], 1, false), 0x7b)
		}},
		{"unregistered_suite", func(p *canonicalMOProvider) MempoolConfig {
			p.spendSet = consensus.NewNativeSuiteSet(0x7b)
			return MempoolConfig{RotationProvider: p}
		}, func(f *canonicalMOFixture) []byte {
			return rewriteSyncTestWitnessSuiteID(t, f.raw(t, f.ops[0], 1, false), 0x7b)
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := newCanonicalMOProvider(t, devnetGenesisChainID)
			g := newCanonicalMOFixture(t, 1, row.cfg(p))
			id := g.installRaw(t, row.raw(g))
			if err := g.applyCoinbase(t); err != nil || g.mp.Contains(id) {
				t.Fatalf("determined native reject err=%v retained=%v", err, g.mp.Contains(id))
			}
		})
	}
	t.Run("unspecified_selection_first_middle_last_and_all", func(t *testing.T) {
		for at, label := range []string{"first", "middle", "last"} {
			t.Run(label, func(t *testing.T) {
				f := newCanonicalMOFixture(t, 3, MempoolConfig{})
				raws, ids := make([][]byte, 3), make([][32]byte, 3)
				for i := range raws {
					raws[i] = f.raw(t, f.ops[i], uint64(i+1), false)
					ids[i] = txID(t, raws[i])
				}
				order := []int{0, 1, 2}
				sort.Slice(order, func(i, j int) bool { return string(ids[order[i]][:]) < string(ids[order[j]][:]) })
				raws[order[at]] = rewriteSyncTestWitnessSuiteID(t, raws[order[at]], 0x7b)
				for i := range raws {
					f.installRaw(t, raws[i])
				}
				mustCanonicalMO(t, "ApplyBlock", f.applyCoinbase(t))
				for i, id := range ids {
					if got, want := f.mp.Contains(id), i != order[at]; got != want {
						t.Fatalf("selection %d retained=%v want=%v", i, got, want)
					}
				}
			})
		}
		p := newCanonicalMOProvider(t, devnetGenesisChainID)
		p.createSet = consensus.NewNativeSuiteSet()
		f := newCanonicalMOFixture(t, 3, MempoolConfig{RotationProvider: p})
		for i := range f.ops {
			f.install(t, f.ops[i], uint64(i+1), false)
		}
		mustCanonicalMO(t, "ApplyBlock", f.applyCoinbase(t))
		if f.mp.Len() != 0 {
			t.Fatalf("all exclusions left %d records", f.mp.Len())
		}
		if outpoints, claims, _ := ownerClaimCount(f.mp.PendingOutpointOwner()); outpoints != 0 || claims != 0 {
			t.Fatalf("all exclusions kept owner rows=%d/%d", outpoints, claims)
		}
	})
	inactive := newCanonicalMOProvider(t, devnetGenesisChainID)
	inactive.descriptors = nil
	inactive.anchor, _ = consensus.SimplicityDeploymentSetAnchor(devnetGenesisChainID, nil)
	h := newCanonicalMOFixture(t, 1, MempoolConfig{RotationProvider: inactive})
	inactiveID := h.install(t, h.ops[0], 1, true)
	if err := h.applyCoinbase(t); err != nil || h.mp.Contains(inactiveID) {
		t.Fatalf("determined inactive err=%v retained=%v", err, h.mp.Contains(inactiveID))
	}
	frozen := newCanonicalMOFixture(t, 1, MempoolConfig{})
	frozenID := frozen.install(t, frozen.ops[0], 1, true)
	if err := frozen.applyCoinbase(t); err != nil || frozen.mp.Contains(frozenID) {
		t.Fatalf("frozen inactive err=%v retained=%v", err, frozen.mp.Contains(frozenID))
	}
	witnessProvider := newCanonicalMOProvider(t, devnetGenesisChainID)
	witness := newCanonicalMOFixture(t, 1, MempoolConfig{RotationProvider: witnessProvider})
	witness.engine.chainState.mu.Lock()
	witness.engine.chainState.Utxos[witness.ops[0]] = consensus.UtxoEntry{Value: 1_000_000, CovenantType: consensus.COV_TYPE_CORE_SIMPLICITY, CovenantData: simplicityCovenantDataForNodeTest([32]byte{}, nil)}
	witness.engine.chainState.mu.Unlock()
	witnessID := witness.installRaw(t, txWithOneInputOneOutput(witness.ops[0].Txid, 0, 900_000, consensus.COV_TYPE_P2PK, witness.address, []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL, Pubkey: make([]byte, 32), Signature: []byte{1}}}))
	if err := witness.applyCoinbase(t); err != nil || witness.mp.Contains(witnessID) {
		t.Fatalf("invalid simplicity witness err=%v retained=%v", err, witness.mp.Contains(witnessID))
	}
	for _, row := range []struct {
		name   string
		mutate func(*canonicalMOProvider)
	}{
		{"unavailable", func(p *canonicalMOProvider) { p.ok = false }},
		{"invalid_evidence", func(p *canonicalMOProvider) { p.anchor[0] ^= 1 }},
		{"provider_error", func(p *canonicalMOProvider) { p.err = errors.New("provider unavailable") }},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := newCanonicalMOProvider(t, devnetGenesisChainID)
			row.mutate(p)
			g := newCanonicalMOFixture(t, 1, MempoolConfig{RotationProvider: p})
			g.install(t, g.ops[0], 1, true)
			var txErr *consensus.TxError
			if err := assertCanonicalMOPlanAbort(t, g); errors.As(err, &txErr) {
				t.Fatalf("plan error leaked consensus tx error: %v", err)
			}
		})
	}
	t.Run("earlier_exclusion_then_abort", func(t *testing.T) {
		p := newCanonicalMOProvider(t, devnetGenesisChainID)
		p.createSet, p.err = consensus.NewNativeSuiteSet(), errors.New("deployment read")
		g := newCanonicalMOFixture(t, 2, MempoolConfig{RotationProvider: p})
		find := func(input int, isCore, high bool) []byte {
			for nonce := uint64(1); nonce < 257; nonce++ {
				raw := g.raw(t, g.ops[input], nonce, isCore)
				if (txID(t, raw)[0] >= 0x80) == high {
					return raw
				}
			}
			return nil
		}
		first, core := find(0, false, false), find(1, true, true)
		if first == nil || core == nil || txID(t, first)[0] >= txID(t, core)[0] {
			t.Fatal("could not construct ordered raw-txid prefixes")
		}
		g.installRaw(t, first)
		g.installRaw(t, core)
		if err := assertCanonicalMOPlanAbort(t, g); err == nil {
			t.Fatal("later provider abort accepted plan")
		}
		if create, _, deploy := p.counts(); create != 1 || deploy != 1 {
			t.Fatalf("observations create=%d deployments=%d", create, deploy)
		}
	})
	local := newCanonicalMOFixture(t, 1, MempoolConfig{SuiteRegistry: unboundAlgSuiteRegistry()})
	local.install(t, local.ops[0], 1, false)
	var localTxErr *consensus.TxError
	if err := assertCanonicalMOPlanAbort(t, local); err == nil {
		t.Fatal("local backend fault did not abort planning")
	} else if errors.As(err, &localTxErr) {
		t.Fatalf("local backend error leaked consensus tx error: %v", err)
	}
	early := newCanonicalMOProvider(t, devnetGenesisChainID)
	i := newCanonicalMOFixture(t, 1, MempoolConfig{RotationProvider: early})
	i.install(t, i.ops[0], 1, true)
	i.mp.mu.Lock()
	for _, entry := range i.mp.txs {
		entry.raw[0] ^= 0xff
	}
	i.mp.mu.Unlock()
	err := i.applyCoinbase(t)
	if !isCanonicalMOTerminalError(err) || !i.engine.persistenceFaulted() {
		t.Fatalf("early invariant err=%v", err)
	}
	if _, ok := i.mp.PendingOutpointOwner().AdmissionContext(); ok {
		t.Fatal("terminal invariant reopened admission")
	}
	if create, spend, deployments := early.counts(); create != 0 || spend != 0 || deployments != 0 {
		t.Fatalf("early invariant read provider create=%d spend=%d deployments=%d", create, spend, deployments)
	}
}

func TestCanonicalMOPlanFailureBeforeFirstWrite(t *testing.T) {
	feeProvider := newCanonicalMOProvider(t, devnetGenesisChainID)
	feeFixture := newCanonicalMOFixture(t, 1, MempoolConfig{RotationProvider: feeProvider})
	feeTxID := feeFixture.install(t, feeFixture.ops[0], 1, false)
	feeFixture.mp.mu.Lock()
	feeFixture.mp.txs[feeTxID].fee.Lo++
	feeFixture.mp.mu.Unlock()
	feeState := feeFixture.engine.chainState.view()
	feeErr := feeFixture.applySpend(t, feeFixture.ops[0], 2)
	if !isCanonicalMOTerminalError(feeErr) || !feeFixture.engine.persistenceFaulted() || feeFixture.engine.chainState.view() != feeState || !feeFixture.mp.Contains(feeTxID) {
		t.Fatalf("stored fee err=%v latch=%v retained=%v", feeErr, feeFixture.engine.persistenceFaulted(), feeFixture.mp.Contains(feeTxID))
	}
	if create, spend, deployments := feeProvider.counts(); create != 0 || spend != 0 || deployments != 0 {
		t.Fatalf("stored fee reached provider create=%d spend=%d deployments=%d", create, spend, deployments)
	}
	withOwner := func(m *Mempool, fn func(*PendingOutpointOwner)) {
		o := m.pendingOutpoints
		o.mu.Lock()
		fn(o)
		o.mu.Unlock()
	}
	rows := []struct {
		name       string
		positional bool
		mutate     func(*Mempool, mempoolSnapshot, int)
	}{
		{"raw", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].raw[0] ^= 0xff }},
		{"tx_map_key", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			delete(m.txs, s.entries[i].txid)
			key := s.entries[i].txid
			key[1] ^= 1
			m.txs[key] = e
		}},
		{"tx_map_missing", true, func(m *Mempool, s mempoolSnapshot, i int) { delete(m.txs, s.entries[i].txid) }},
		{"tx_map_extra_cardinality", true, func(m *Mempool, _ mempoolSnapshot, i int) { m.txs[[32]byte{0xfa, byte(i)}] = nil }},
		{"txid", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].txid[0] ^= 1 }},
		{"wtxid", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].wtxid[0] ^= 1 }},
		{"wtxid_map_key", true, func(m *Mempool, s mempoolSnapshot, i int) {
			key := s.entries[i].wtxid
			value := m.wtxids[key]
			delete(m.wtxids, key)
			key[1] ^= 1
			m.wtxids[key] = value
		}},
		{"wtxid_map_value", true, func(m *Mempool, s mempoolSnapshot, i int) { m.wtxids[s.entries[i].wtxid] = [32]byte{} }},
		{"wtxid_map_missing", true, func(m *Mempool, s mempoolSnapshot, i int) { delete(m.wtxids, s.entries[i].wtxid) }},
		{"wtxid_map_extra_cardinality", true, func(m *Mempool, _ mempoolSnapshot, i int) { m.wtxids[[32]byte{0xfb, byte(i)}] = [32]byte{} }},
		{"token", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].token.seq++ }},
		{"fee_lo", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].fee.Lo++ }},
		{"fee_hi", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].fee.Hi++ }},
		{"weight_zero", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].weight = 0 }},
		{"weight", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].weight++ }},
		{"size_zero", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].size = 0 }},
		{"size", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].size-- }},
		{"size_over_cap", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].size = m.maxBytes + 1 }},
		{"admission_seq_zero", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].admissionSeq = 0 }},
		{"admission_seq_mismatch", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].admissionSeq += 10 }},
		{"input_count", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			e.inputs = append(e.inputs, e.inputs[0])
		}},
		{"input_value", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].inputs[0].Vout++ }},
		{"source", true, func(m *Mempool, s mempoolSnapshot, i int) { m.txs[s.entries[i].txid].source = "bad" }},
		{"duplicate_sequence", true, func(m *Mempool, s mempoolSnapshot, i int) {
			m.txs[s.entries[i].txid].admissionSeq = m.txs[s.entries[(i+1)%len(s.entries)].txid].admissionSeq
		}},
		{"chain_id", false, func(m *Mempool, _ mempoolSnapshot, _ int) { m.chainID[0] ^= 1 }},
		{"last_sequence_high_water", false, func(m *Mempool, _ mempoolSnapshot, _ int) { m.lastAdmissionSeq = 0 }},
		{"used_bytes", false, func(m *Mempool, _ mempoolSnapshot, _ int) { m.usedBytes++ }},
		{"current_min_fee_rate", false, func(m *Mempool, _ mempoolSnapshot, _ int) { m.currentMinFeeRate++ }},
		{"max_txs", false, func(m *Mempool, _ mempoolSnapshot, _ int) { m.maxTxs = 0 }},
		{"max_bytes", false, func(m *Mempool, _ mempoolSnapshot, _ int) { m.maxBytes = 0 }},
		{"pending_owner_pointer", false, func(m *Mempool, _ mempoolSnapshot, _ int) {
			m.pendingOutpoints = newPendingOutpointOwner(PendingOutpointTip{})
		}},
		{"owner_in_transition", false, func(m *Mempool, _ mempoolSnapshot, _ int) {
			withOwner(m, func(o *PendingOutpointOwner) { o.inTransition = false })
		}},
		{"owner_stable_tip", false, func(m *Mempool, _ mempoolSnapshot, _ int) {
			withOwner(m, func(o *PendingOutpointOwner) { o.stableTip.Height++ })
		}},
		{"token_high_water", false, func(m *Mempool, _ mempoolSnapshot, _ int) {
			withOwner(m, func(o *PendingOutpointOwner) { o.tokenHighWater = 0 })
		}},
		{"owner_generation_high_water", false, func(m *Mempool, _ mempoolSnapshot, _ int) {
			withOwner(m, func(o *PendingOutpointOwner) { o.generation++ })
		}},
		{"claim_generation_above_high_water", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) { o.byToken[e.token].generation = ^uint64(0) })
		}},
		{"claim_txid", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) { o.byToken[e.token].txid[0] ^= 1 })
		}},
		{"by_token_missing", true, func(m *Mempool, s mempoolSnapshot, i int) {
			withOwner(m, func(o *PendingOutpointOwner) { delete(o.byToken, s.entries[i].token) })
		}},
		{"by_token_extra_cardinality", true, func(m *Mempool, _ mempoolSnapshot, i int) {
			withOwner(m, func(o *PendingOutpointOwner) {
				token := PendingOutpointToken{owner: o, seq: o.tokenHighWater + uint64(i) + 1}
				o.byToken[token] = &pendingOutpointClaim{token: token}
			})
		}},
		{"claim_token_field", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) { o.byToken[e.token].token = PendingOutpointToken{} })
		}},
		{"claim_token_key", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) {
				claim := o.byToken[e.token]
				delete(o.byToken, e.token)
				o.byToken[PendingOutpointToken{owner: o, seq: e.token.seq + 9}] = claim
			})
		}},
		{"claim_owner", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) {
				o.byToken[e.token].token.owner = newPendingOutpointOwner(PendingOutpointTip{})
			})
		}},
		{"claim_sequence", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) { o.byToken[e.token].token.seq = o.tokenHighWater + uint64(i) + 100 })
		}},
		{"claim_domain", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) { o.byToken[e.token].domain = PendingOutpointDA })
		}},
		{"claim_generation", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) { o.byToken[e.token].generation++ })
		}},
		{"claim_finalized", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) { o.byToken[e.token].finalized = false })
		}},
		{"claim_input_count", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) {
				claim := o.byToken[e.token]
				claim.inputs = append(claim.inputs, claim.inputs[0])
			})
		}},
		{"claim_input_value", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) { o.byToken[e.token].inputs[0].Vout++ })
		}},
		{"by_outpoint_missing", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) { delete(o.byOutpoint, e.inputs[0]) })
		}},
		{"by_outpoint_extra_cardinality", true, func(m *Mempool, _ mempoolSnapshot, i int) {
			withOwner(m, func(o *PendingOutpointOwner) {
				o.byOutpoint[consensus.Outpoint{Txid: [32]byte{0xfc, byte(i)}}] = pendingOutpointRow{}
			})
		}},
		{"by_outpoint_row_token", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) {
				row := o.byOutpoint[e.inputs[0]]
				row.token.seq++
				o.byOutpoint[e.inputs[0]] = row
			})
		}},
		{"by_outpoint_row_txid", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) {
				row := o.byOutpoint[e.inputs[0]]
				row.txid[0] ^= 1
				o.byOutpoint[e.inputs[0]] = row
			})
		}},
		{"record_claim_bijection", true, func(m *Mempool, s mempoolSnapshot, i int) {
			e := m.txs[s.entries[i].txid]
			withOwner(m, func(o *PendingOutpointOwner) { o.byToken[e.token].txid = [32]byte{} })
		}},
	}
	// These values can be self-consistent when captured, so only a post-capture change is an intrinsic stale-image failure.
	freshnessOnly := map[string]bool{"current_min_fee_rate": true, "owner_stable_tip": true, "owner_generation_high_water": true, "claim_generation": true}
	for _, row := range rows {
		indexes := []int{1}
		if row.positional {
			indexes = []int{0, 1, 2}
		}
		for _, index := range indexes {
			for _, mode := range []string{"pre_capture", "live_drift"} {
				if freshnessOnly[row.name] && mode == "pre_capture" {
					continue
				}
				position := []string{"first", "middle", "last"}[index]
				t.Run(row.name+"/"+mode+"/"+position, func(t *testing.T) {
					f := newCanonicalMOFixture(t, 3, MempoolConfig{})
					for i := range f.ops {
						f.add(t, f.ops[i], uint64(i+1))
					}
					owner := f.mp.PendingOutpointOwner()
					if _, err := owner.beginTransition(); err != nil {
						t.Fatalf("beginTransition: %v", err)
					}
					defer owner.endTransitionAborted()
					baseline := mustCanonicalMOSnapshot(t, f.mp)
					f.mp.mu.Lock()
					row.mutate(f.mp, baseline, index)
					f.mp.mu.Unlock()
					snapshot := baseline
					if mode == "pre_capture" {
						snapshot = mustCanonicalMOSnapshot(t, f.mp)
					}
					before := canonicalMOImageFingerprint(t, f.mp, 0)
					_, err := prepareCanonicalMempoolPlan(f.mp, snapshot, f.engine.chainState, 0, 1, f.engine.cfg.ChainID)
					if !isCanonicalMOTerminalError(err) || before != canonicalMOImageFingerprint(t, f.mp, 0) {
						t.Fatalf("planning err=%v mutated M/O", err)
					}
					if row.name == "raw" && !strings.Contains(err.Error(), fmt.Sprintf("%x", snapshot.entries[index].txid)) {
						t.Fatalf("raw error=%v, want txid=%x", err, snapshot.entries[index].txid)
					}
				})
			}
		}
	}
	runMixed := func(t *testing.T, name string, mutate func(*Mempool, *PendingOutpointOwner, mempoolEntry, mempoolEntry)) {
		t.Helper()
		f := newCanonicalMOFixture(t, 3, MempoolConfig{})
		for i := range f.ops {
			f.add(t, f.ops[i], uint64(i+1))
		}
		o := f.mp.PendingOutpointOwner()
		_, beginErr := o.beginTransition()
		mustCanonicalMO(t, "beginTransition", beginErr)
		defer o.endTransitionAborted()
		snapshot := mustCanonicalMOSnapshot(t, f.mp)
		low, high := snapshot.entries[0], snapshot.entries[len(snapshot.entries)-1]
		f.mp.mu.Lock()
		o.mu.Lock()
		mutate(f.mp, o, low, high)
		o.mu.Unlock()
		f.mp.mu.Unlock()
		before := canonicalMOImageFingerprint(t, f.mp, 0)
		_, err := prepareCanonicalMempoolPlan(f.mp, snapshot, f.engine.chainState, 0, 1, f.engine.cfg.ChainID)
		if !isCanonicalMOTerminalError(err) || before != canonicalMOImageFingerprint(t, f.mp, 0) || !strings.Contains(err.Error(), fmt.Sprintf("%x", low.txid)) {
			t.Fatalf("%s err=%v want lower raw txid=%x", name, err, low.txid)
		}
	}
	runMiddleStructural := func(t *testing.T, name, want string, wantMiddle bool, mutate func(*Mempool, *PendingOutpointOwner, mempoolEntry, mempoolEntry, mempoolEntry)) {
		t.Helper()
		f := newCanonicalMOFixture(t, 3, MempoolConfig{})
		for i := range f.ops {
			f.add(t, f.ops[i], uint64(i+1))
		}
		o := f.mp.PendingOutpointOwner()
		_, beginErr := o.beginTransition()
		mustCanonicalMO(t, "beginTransition", beginErr)
		defer o.endTransitionAborted()
		entries := mustCanonicalMOSnapshot(t, f.mp).entries
		first, middle, last := entries[0], entries[1], entries[2]
		f.mp.mu.Lock()
		o.mu.Lock()
		mutate(f.mp, o, first, middle, last)
		o.mu.Unlock()
		f.mp.mu.Unlock()
		snapshot := mustCanonicalMOSnapshot(t, f.mp)
		before := canonicalMOImageFingerprint(t, f.mp, 0)
		_, err := prepareCanonicalMempoolPlan(f.mp, snapshot, f.engine.chainState, 0, 1, f.engine.cfg.ChainID)
		if !isCanonicalMOTerminalError(err) || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), fmt.Sprintf("%x", last.txid)) || (wantMiddle && !strings.Contains(err.Error(), fmt.Sprintf("%x", middle.txid))) || before != canonicalMOImageFingerprint(t, f.mp, 0) {
			t.Fatalf("%s err=%v want=%q middle=%x later=%x", name, err, want, middle.txid, last.txid)
		}
	}
	t.Run("middle_duplicate_admission_before_later_claim", func(t *testing.T) {
		runMiddleStructural(t, "middle_duplicate_admission_before_later_claim", "duplicate mempool snapshot admission_seq", true, func(m *Mempool, o *PendingOutpointOwner, first, middle, last mempoolEntry) {
			m.txs[middle.txid].admissionSeq = m.txs[first.txid].admissionSeq
			o.byToken[last.token].finalized = false
		})
	})
	t.Run("middle_duplicate_wtxid_before_later_claim", func(t *testing.T) {
		runMiddleStructural(t, "middle_duplicate_wtxid_before_later_claim", "duplicate mempool snapshot wtxid", true, func(m *Mempool, o *PendingOutpointOwner, first, middle, last mempoolEntry) {
			m.txs[middle.txid].wtxid = m.txs[first.txid].wtxid
			o.byToken[last.token].finalized = false
		})
	})
	t.Run("middle_byte_cap_before_later_claim", func(t *testing.T) {
		runMiddleStructural(t, "middle_byte_cap_before_later_claim", "mempool snapshot exceeds byte cap", false, func(m *Mempool, o *PendingOutpointOwner, first, middle, last mempoolEntry) {
			m.maxBytes = m.txs[first.txid].size + m.txs[middle.txid].size - 1
			o.byToken[last.token].finalized = false
		})
	})
	t.Run("low_claim_before_higher_raw", func(t *testing.T) {
		runMixed(t, "low_claim_before_higher_raw", func(m *Mempool, o *PendingOutpointOwner, low, high mempoolEntry) {
			o.byToken[low.token].txid[0] ^= 1
			m.txs[high.txid].raw[0] ^= 1
		})
	})
	t.Run("bound_standard_domain_before_higher_standard", func(t *testing.T) {
		runMixed(t, "bound_standard_domain_before_higher_standard", func(_ *Mempool, o *PendingOutpointOwner, low, high mempoolEntry) {
			o.byToken[low.token].domain = PendingOutpointDA
			o.byToken[high.token].finalized = false
		})
	})
	t.Run("dual_claim_raw_txid_precedes_token_order", func(t *testing.T) {
		f := newCanonicalMOFixture(t, 3, MempoolConfig{})
		for i := range f.ops {
			f.add(t, f.ops[i], uint64(i+1))
		}
		o := f.mp.PendingOutpointOwner()
		_, beginErr := o.beginTransition()
		mustCanonicalMO(t, "beginTransition", beginErr)
		defer o.endTransitionAborted()
		snapshot := mustCanonicalMOSnapshot(t, f.mp)
		low, high := snapshot.entries[0], snapshot.entries[len(snapshot.entries)-1]
		for i := range snapshot.pending.claims {
			if snapshot.pending.claims[i].token == high.token {
				snapshot.pending.claims[0], snapshot.pending.claims[i] = snapshot.pending.claims[i], snapshot.pending.claims[0]
				break
			}
		}
		f.mp.mu.Lock()
		o.mu.Lock()
		o.byToken[low.token].txid[0] ^= 1
		o.byToken[high.token].txid[0] ^= 1
		o.mu.Unlock()
		f.mp.mu.Unlock()
		_, err := prepareCanonicalMempoolPlan(f.mp, snapshot, f.engine.chainState, 0, 1, f.engine.cfg.ChainID)
		if !isCanonicalMOTerminalError(err) || !strings.Contains(err.Error(), fmt.Sprintf("%x", low.txid)) {
			t.Fatalf("claim precedence err=%v want lower raw txid=%x", err, low.txid)
		}
	})
	t.Run("orphan_standard_precedes_malformed_nonstandard", func(t *testing.T) {
		f := newCanonicalMOFixture(t, 3, MempoolConfig{})
		for i := range f.ops {
			f.add(t, f.ops[i], uint64(i+1))
		}
		o := f.mp.PendingOutpointOwner()
		_, beginErr := o.beginTransition()
		mustCanonicalMO(t, "beginTransition", beginErr)
		defer o.endTransitionAborted()
		var orphanID [32]byte
		orphanID[0] = 1
		f.mp.mu.Lock()
		o.mu.Lock()
		o.tokenHighWater += 2
		orphanToken := PendingOutpointToken{owner: o, seq: o.tokenHighWater - 1}
		orphanInput := consensus.Outpoint{Txid: [32]byte{0xe1}, Vout: 1}
		o.byToken[orphanToken] = &pendingOutpointClaim{token: orphanToken, domain: PendingOutpointStandardMempool, txid: orphanID, inputs: []consensus.Outpoint{orphanInput}, generation: o.generation, finalized: true}
		o.byOutpoint[orphanInput] = pendingOutpointRow{token: orphanToken, txid: orphanID}
		badToken := PendingOutpointToken{owner: o, seq: o.tokenHighWater}
		o.byToken[badToken] = &pendingOutpointClaim{token: badToken, domain: PendingOutpointDomain(255), txid: [32]byte{2}, inputs: []consensus.Outpoint{{Txid: [32]byte{0xe2}}}, generation: o.generation}
		o.mu.Unlock()
		f.mp.mu.Unlock()
		snapshot := mustCanonicalMOSnapshot(t, f.mp)
		_, err := prepareCanonicalMempoolPlan(f.mp, snapshot, f.engine.chainState, 0, 1, f.engine.cfg.ChainID)
		if !isCanonicalMOTerminalError(err) || !strings.Contains(err.Error(), fmt.Sprintf("%x", orphanID)) {
			t.Fatalf("orphan precedence err=%v want standard=%x", err, orphanID)
		}
	})
	t.Run("ordered_da_claim_shape_before_later_malformed", func(t *testing.T) {
		for _, row := range []struct {
			name, family string
			mutate       func(*pendingOutpointClaim)
			duplicate    bool
		}{
			{"generation", "generation above high-water", func(claim *pendingOutpointClaim) { claim.generation++ }, false},
			{"duplicate_inputs", "duplicate pending-outpoint input", func(claim *pendingOutpointClaim) { claim.inputs = append(claim.inputs, claim.inputs[0]) }, false},
			{"duplicate_token", "duplicate pending-outpoint token claim", nil, true},
		} {
			t.Run(row.name, func(t *testing.T) {
				f := newCanonicalMOFixture(t, 1, MempoolConfig{})
				f.add(t, f.ops[0], 1)
				o := f.mp.PendingOutpointOwner()
				_, beginErr := o.beginTransition()
				mustCanonicalMO(t, "beginTransition", beginErr)
				defer o.endTransitionAborted()
				lowerID, laterID := [32]byte{1}, [32]byte{2}
				lowerInput := consensus.Outpoint{Txid: lowerID}
				f.mp.mu.Lock()
				o.mu.Lock()
				o.tokenHighWater += 2
				lowerToken := PendingOutpointToken{owner: o, seq: o.tokenHighWater - 1}
				lower := &pendingOutpointClaim{token: lowerToken, domain: PendingOutpointDA, txid: lowerID, inputs: []consensus.Outpoint{lowerInput}, generation: o.generation, finalized: true}
				if row.mutate != nil {
					row.mutate(lower)
				}
				o.byToken[lowerToken], o.byOutpoint[lowerInput] = lower, pendingOutpointRow{token: lowerToken, txid: lowerID}
				laterToken := PendingOutpointToken{owner: o, seq: o.tokenHighWater}
				o.byToken[laterToken] = &pendingOutpointClaim{token: laterToken, domain: PendingOutpointDA, txid: laterID, generation: o.generation, finalized: true}
				o.mu.Unlock()
				f.mp.mu.Unlock()
				snapshot := mustCanonicalMOSnapshot(t, f.mp)
				if row.duplicate {
					for i := range snapshot.pending.claims {
						if snapshot.pending.claims[i].token == lowerToken {
							snapshot.pending.claims = append(snapshot.pending.claims, snapshot.pending.claims[i])
							break
						}
					}
				}
				before := canonicalMOImageFingerprint(t, f.mp, 0)
				_, err := prepareCanonicalMempoolPlan(f.mp, snapshot, f.engine.chainState, 0, 1, f.engine.cfg.ChainID)
				if !isCanonicalMOTerminalError(err) || !strings.Contains(err.Error(), row.family) || !strings.Contains(err.Error(), fmt.Sprintf("%x", lowerID)) || strings.Contains(err.Error(), fmt.Sprintf("%x", laterID)) || before != canonicalMOImageFingerprint(t, f.mp, 0) {
					t.Fatalf("%s err=%v lower=%x later=%x", row.name, err, lowerID, laterID)
				}
			})
		}
	})
	t.Run("bound_duplicate_inputs_before_later_da", func(t *testing.T) {
		f := newCanonicalMOFixture(t, 1, MempoolConfig{})
		inputs := []consensus.Outpoint{f.ops[0], f.ops[0]}
		raw := mustBuildSignedTransferTxForSyncTest(t, f.engine.chainState.Utxos, inputs, 1_800_000, 100_000, 1, f.signer, f.address, f.address)
		tx, txid, wtxid, consumed, err := consensus.ParseTx(raw)
		if err != nil || consumed != len(raw) {
			t.Fatalf("ParseTx(bound duplicate) consumed=%d err=%v", consumed, err)
		}
		weight, _, _, err := consensus.TxWeightAndStats(tx)
		mustCanonicalMO(t, "TxWeightAndStats(bound duplicate)", err)
		o := f.mp.PendingOutpointOwner()
		_, beginErr := o.beginTransition()
		mustCanonicalMO(t, "beginTransition", beginErr)
		defer o.endTransitionAborted()
		laterID := [32]byte{2}
		f.mp.mu.Lock()
		o.mu.Lock()
		o.tokenHighWater += 2
		token := PendingOutpointToken{owner: o, seq: o.tokenHighWater - 1}
		entry := &mempoolEntry{raw: append([]byte(nil), raw...), txid: txid, wtxid: wtxid, inputs: append([]consensus.Outpoint(nil), inputs...), token: token, fee: consensus.Uint128FromU64(100_000), weight: weight, size: len(raw), admissionSeq: 1, source: mempoolTxSourceLocal}
		claim := &pendingOutpointClaim{token: token, domain: PendingOutpointStandardMempool, txid: txid, inputs: append([]consensus.Outpoint(nil), inputs...), generation: o.generation, finalized: true}
		f.mp.txs[txid], f.mp.wtxids[wtxid], f.mp.usedBytes, f.mp.lastAdmissionSeq = entry, txid, entry.size, entry.admissionSeq
		o.byToken[token], o.byOutpoint[inputs[0]] = claim, pendingOutpointRow{token: token, txid: txid}
		laterToken := PendingOutpointToken{owner: o, seq: o.tokenHighWater}
		o.byToken[laterToken] = &pendingOutpointClaim{token: laterToken, domain: PendingOutpointDA, txid: laterID, generation: o.generation, finalized: true}
		o.mu.Unlock()
		f.mp.mu.Unlock()
		snapshot := mustCanonicalMOSnapshot(t, f.mp)
		before := canonicalMOImageFingerprint(t, f.mp, 0)
		_, err = prepareCanonicalMempoolPlan(f.mp, snapshot, f.engine.chainState, 0, 1, f.engine.cfg.ChainID)
		if !isCanonicalMOTerminalError(err) || !strings.Contains(err.Error(), "duplicate pending-outpoint input") || strings.Contains(err.Error(), fmt.Sprintf("%x", laterID)) || before != canonicalMOImageFingerprint(t, f.mp, 0) {
			t.Fatalf("bound duplicate err=%v later=%x", err, laterID)
		}
	})
	t.Run("input_order_first_middle_last", func(t *testing.T) {
		for _, row := range []struct {
			name  string
			claim bool
		}{{"record", false}, {"claim", true}} {
			t.Run(row.name, func(t *testing.T) {
				for index, label := range []string{"first", "middle", "last"} {
					t.Run(label, func(t *testing.T) {
						f := newCanonicalMOFixture(t, 6, MempoolConfig{})
						for i := 0; i < 3; i++ {
							raw := mustBuildSignedTransferTxForSyncTest(t, f.engine.chainState.Utxos, f.ops[2*i:2*i+2], 1_800_000, 100_000, uint64(i+1), f.signer, f.address, f.address)
							f.installRaw(t, raw)
						}
						o := f.mp.PendingOutpointOwner()
						_, beginErr := o.beginTransition()
						mustCanonicalMO(t, "beginTransition", beginErr)
						snapshot := mustCanonicalMOSnapshot(t, f.mp)
						f.mp.mu.Lock()
						e := f.mp.txs[snapshot.entries[index].txid]
						if row.claim {
							o.mu.Lock()
							claim := o.byToken[e.token]
							claim.inputs[0], claim.inputs[1] = claim.inputs[1], claim.inputs[0]
							o.mu.Unlock()
						} else {
							e.inputs[0], e.inputs[1] = e.inputs[1], e.inputs[0]
						}
						f.mp.mu.Unlock()
						_, err := prepareCanonicalMempoolPlan(f.mp, snapshot, f.engine.chainState, 0, 1, f.engine.cfg.ChainID)
						o.endTransitionAborted()
						if !isCanonicalMOTerminalError(err) || !strings.Contains(err.Error(), fmt.Sprintf("%x", snapshot.entries[index].txid)) {
							t.Fatalf("%s input order err=%v want txid=%x", row.name, err, snapshot.entries[index].txid)
						}
					})
				}
			})
		}
	})
	t.Run("direct_recheck_before_publication", func(t *testing.T) {
		f := newCanonicalMOFixture(t, 1, MempoolConfig{})
		f.add(t, f.ops[0], 1)
		before := canonicalMOImageFingerprint(t, f.mp, 0)
		index, err := f.store.CanonicalIndexSnapshot()
		mustCanonicalMO(t, "CanonicalIndexSnapshot", err)
		tr, err := f.engine.beginCanonicalTransition(nil)
		mustCanonicalMO(t, "beginCanonicalTransition", err)
		stale := chainTipScalarsOf(f.engine.chainState)
		stale.height++
		write, writes := writeFileAtomicFn, 0
		t.Cleanup(func() { writeFileAtomicFn = write })
		writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error { writes++; return write(path, data, mode) }
		_, err = f.engine.prepareCanonicalFenceImage(tr, &canonicalTransitionPlan{oldSequence: index, priorTip: stale, final: f.engine.chainState})
		if endErr := tr.end(err); endErr != err || err == nil || writes != 0 || f.engine.persistenceFaulted() { //nolint:errorlint // Exact passthrough identity is the behavior under test.
			t.Fatalf("prepublication recheck err=%v end=%v writes=%d latch=%v", err, endErr, writes, f.engine.persistenceFaulted())
		}
		if before != canonicalMOImageFingerprint(t, f.mp, 1) {
			t.Fatalf("prepublication recheck M/O=%s", canonicalMOImageFingerprint(t, f.mp, 1))
		}
		if _, ok := f.mp.PendingOutpointOwner().AdmissionContext(); !ok {
			t.Fatal("prepublication recheck left admission closed")
		}
	})
}

// TestCanonicalMOPlanRefusedCommitPublishesNothing replaces the legacy rollback
// row: with publication moved AFTER the one index commit there is nothing to
// restore, so a refused commit must leave the M/O image untouched, write the
// index exactly once, reopen admission and never latch. The third case proves
// the same for a tip that moves before the fence recheck, where no index write
// happens at all.
func TestCanonicalMOPlanRefusedCommitPublishesNothing(t *testing.T) {
	f := newCanonicalMOFixture(t, 1, MempoolConfig{})
	f.add(t, f.ops[0], 1)
	f.mp.SetCurrentMinFeeRateForTest(8)
	before := canonicalMOImageFingerprint(t, f.mp, 0)
	write := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = write })
	indexWrites := 0
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path == f.store.indexPath {
			indexWrites++
			return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
		}
		return write(path, data, mode)
	}
	if err := f.applyCoinbase(t); err == nil || f.engine.persistenceFaulted() {
		t.Fatalf("refused commit err=%v latch=%v", err, f.engine.persistenceFaulted())
	}
	if before != canonicalMOImageFingerprint(t, f.mp, 1) {
		t.Fatalf("refused commit M/O=%s", canonicalMOImageFingerprint(t, f.mp, 1))
	}
	if indexWrites != 1 {
		t.Fatalf("canonical index writes=%d, want exactly 1", indexWrites)
	}
	if _, ok := f.mp.PendingOutpointOwner().AdmissionContext(); !ok {
		t.Fatal("refused commit left admission closed")
	}
	writeFileAtomicFn = write

	h := newCanonicalMOFixture(t, 1, MempoolConfig{})
	mustCanonicalMO(t, "ApplyBlock(disconnect predecessor)", h.applyCoinbase(t))
	retained := h.install(t, h.ops[0], 1, true)
	beforeDisconnect, beforeView := canonicalMOImageFingerprint(t, h.mp, 0), h.engine.chainState.view()
	disconnectWrites := 0
	withWriteFileAtomicFn(t, func(path string, data []byte, mode os.FileMode) error {
		if path == h.store.indexPath {
			disconnectWrites++
			return newAtomicWriteError(atomicWriteBeforeNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
		}
		return write(path, data, mode)
	})
	if _, err := h.engine.DisconnectTip(); err == nil || h.engine.persistenceFaulted() {
		t.Fatalf("refused disconnect err=%v latch=%v", err, h.engine.persistenceFaulted())
	}
	if disconnectWrites != 1 {
		t.Fatalf("disconnect canonical index writes=%d, want exactly 1", disconnectWrites)
	}
	if beforeDisconnect != canonicalMOImageFingerprint(t, h.mp, 1) || h.engine.chainState.view() != beforeView || !h.mp.Contains(retained) {
		t.Fatalf("refused disconnect M/O=%s", canonicalMOImageFingerprint(t, h.mp, 1))
	}
	if _, ok := h.mp.PendingOutpointOwner().AdmissionContext(); !ok {
		t.Fatal("refused disconnect left admission closed")
	}
}

func TestCanonicalMOPlanConcurrentAdmission(t *testing.T) {
	for _, remove := range []bool{false, true} {
		name := "add"
		if remove {
			name = "remove"
		}
		t.Run(name, func(t *testing.T) {
			p := newCanonicalMOProvider(t, devnetGenesisChainID)
			p.entered, p.release = make(chan struct{}, 1), make(chan struct{})
			f := newCanonicalMOFixture(t, 2, MempoolConfig{RotationProvider: p})
			core := f.install(t, f.ops[0], 1, true)
			raw := f.raw(t, f.ops[1], 2, false)
			if remove {
				mustCanonicalMO(t, "AddTx(resident)", f.mp.AddTx(raw))
			}
			owner := f.mp.PendingOutpointOwner()
			before := mustCanonicalMOSnapshot(t, f.mp)
			entryFor := func(txid [32]byte) mempoolEntry {
				for i := range before.entries {
					if before.entries[i].txid == txid {
						return before.entries[i]
					}
				}
				t.Fatalf("missing expected entry %x", txid)
				return mempoolEntry{}
			}
			claimFor := func(token PendingOutpointToken) pendingOutpointClaim {
				for i := range before.pending.claims {
					if before.pending.claims[i].token == token {
						return before.pending.claims[i]
					}
				}
				t.Fatalf("missing expected claim %d", token.seq)
				return pendingOutpointClaim{}
			}
			coreEntry, coreClaim := entryFor(core), claimFor(entryFor(core).token)
			f.mp.mu.RLock()
			floor, maxTxs, maxBytes := f.mp.currentMinFeeRate, f.mp.maxTxs, f.mp.maxBytes
			f.mp.mu.RUnlock()
			assertImage := func(entries []mempoolEntry, claims []pendingOutpointClaim, used int, seq, high, generation uint64, tip PendingOutpointTip) {
				t.Helper()
				f.mp.mu.RLock()
				defer f.mp.mu.RUnlock()
				owner.mu.Lock()
				defer owner.mu.Unlock()
				if f.mp.pendingOutpoints != owner || f.mp.usedBytes != used || f.mp.lastAdmissionSeq != seq || f.mp.currentMinFeeRate != floor || f.mp.maxTxs != maxTxs || f.mp.maxBytes != maxBytes || len(f.mp.txs) != len(entries) || len(f.mp.wtxids) != len(entries) || owner.inTransition || owner.tokenHighWater != high || owner.generation != generation || owner.stableTip != tip || len(owner.byToken) != len(claims) {
					t.Fatal("unexpected M/O header")
				}
				outpoints := 0
				for i := range entries {
					entry := entries[i]
					live, ok := f.mp.txs[entry.txid]
					if !ok || !reflect.DeepEqual(*live, entry) || f.mp.wtxids[entry.wtxid] != entry.txid {
						t.Fatal("unexpected record image")
					}
				}
				for i := range claims {
					claim := claims[i]
					live, ok := owner.byToken[claim.token]
					if !ok || !reflect.DeepEqual(*live, claim) {
						t.Fatal("unexpected claim image")
					}
					for _, input := range claim.inputs {
						row, ok := owner.byOutpoint[input]
						if !ok || row.token != claim.token || row.txid != claim.txid {
							t.Fatal("unexpected outpoint image")
						}
						outpoints++
					}
				}
				if len(owner.byOutpoint) != outpoints {
					t.Fatal("unexpected outpoint cardinality")
				}
			}
			height := f.engine.chainState.Height + 1
			subsidy := consensus.BlockSubsidyBig(height, f.engine.chainState.AlreadyGenerated.Big())
			block := buildSingleTxBlock(t, f.engine.chainState.TipHash, f.target, reorgTestTimestamp(f.now), coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy))
			apply, operation, started := make(chan error, 1), make(chan error, 1), make(chan struct{})
			released, applyDone, operationStarted, operationDone := false, false, false, false
			releasePlanner := func() {
				if !released {
					close(p.release)
					released = true
				}
			}
			waitApply := func(label string) error { err := awaitCanonicalMOError(t, apply, label); applyDone = true; return err }
			waitOperation := func(label string) error {
				err := awaitCanonicalMOError(t, operation, label)
				operationDone = true
				return err
			}
			t.Cleanup(func() {
				releasePlanner()
				if !applyDone {
					_ = waitApply("apply cleanup")
				}
				if operationStarted && !operationDone {
					_ = waitOperation("operation cleanup")
				}
			})
			go func() { _, err := f.engine.ApplyBlock(block, nil); apply <- err }()
			select {
			case <-p.entered:
			case <-time.After(time.Second):
				releasePlanner()
				_ = waitApply("apply")
				t.Fatal("plan did not reach provider barrier")
			}
			if _, _, deployments := p.counts(); deployments != 1 {
				releasePlanner()
				_ = waitApply("apply")
				t.Fatalf("provider barrier deployments=%d", deployments)
			}
			if _, ok := f.mp.PendingOutpointOwner().AdmissionContext(); ok {
				releasePlanner()
				_ = waitApply("apply")
				t.Fatal("admission reopened during plan")
			}
			barrier := canonicalMOImageFingerprint(t, f.mp, 0)
			caller := "(*Mempool).addTxWithSource"
			if remove {
				_, _, wtxid, _, err := consensus.ParseTx(raw)
				mustCanonicalMO(t, "ParseTx(conflict)", err)
				conflict := buildMultiTxBlock(t, f.engine.chainState.TipHash, f.target, reorgTestTimestamp(f.now+1), coinbaseWithWitnessCommitmentAndP2PKValueForWtxids(t, height, subsidy+100_000, [][32]byte{{}, wtxid}), raw)
				caller = "(*Mempool).withLockedParsedBlock"
				operationStarted = true
				go func() { close(started); operation <- f.mp.RemoveConflicting(conflict) }()
			} else {
				operationStarted = true
				go func() { close(started); operation <- f.mp.AddTx(raw) }()
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				releasePlanner()
				_ = waitApply("apply")
				t.Fatal("admission operation did not start behind the plan barrier")
			}
			awaitCanonicalMOAdmissionRLock(t, caller)
			if barrier != canonicalMOImageFingerprint(t, f.mp, 0) {
				t.Fatalf("operation mutated M/O before admission guard release image=%s", canonicalMOImageFingerprint(t, f.mp, 0))
			}
			releasePlanner()
			mustCanonicalMO(t, "ApplyBlock", waitApply("apply"))
			mustCanonicalMO(t, "operation", waitOperation("operation"))
			view := f.engine.chainState.view()
			tip := PendingOutpointTip{HasTip: view.hasTip, Height: view.height, Hash: view.tipHash}
			if remove {
				assertImage([]mempoolEntry{coreEntry}, []pendingOutpointClaim{coreClaim}, coreEntry.size, before.lastAdmissionSeq, before.pending.tokenHighWater, before.pending.generationHighWater+1, tip)
			} else {
				tx, txid, wtxid, consumed, err := consensus.ParseTx(raw)
				if err != nil || consumed != len(raw) {
					t.Fatalf("ParseTx(add) consumed=%d err=%v", consumed, err)
				}
				weight, _, _, err := consensus.TxWeightAndStats(tx)
				mustCanonicalMO(t, "TxWeightAndStats(add)", err)
				token := PendingOutpointToken{owner: owner, seq: before.pending.tokenHighWater + 1}
				added := mempoolEntry{raw: append([]byte(nil), raw...), txid: txid, wtxid: wtxid, inputs: []consensus.Outpoint{f.ops[1]}, token: token, fee: consensus.Uint128FromU64(100_000), weight: weight, size: len(raw), admissionSeq: before.lastAdmissionSeq + 1, source: mempoolTxSourceLocal}
				claim := pendingOutpointClaim{token: token, domain: PendingOutpointStandardMempool, txid: txid, inputs: []consensus.Outpoint{f.ops[1]}, generation: before.pending.generationHighWater + 1, finalized: true}
				assertImage([]mempoolEntry{coreEntry, added}, []pendingOutpointClaim{coreClaim, claim}, coreEntry.size+added.size, added.admissionSeq, token.seq, claim.generation, tip)
			}
		})
	}
}

func mustCanonicalMOSnapshot(t *testing.T, mp *Mempool) mempoolSnapshot {
	snapshot, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}
	return snapshot
}

func canonicalMOImageFingerprint(t *testing.T, mp *Mempool, generationAdvance uint64) string {
	t.Helper()
	var out strings.Builder
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	owner := mp.pendingOutpoints
	fmt.Fprintf(&out, "m=%p owner=%p used=%d seq=%d floor=%d limits=%d/%d", mp, owner, mp.usedBytes, mp.lastAdmissionSeq, mp.currentMinFeeRate, mp.maxTxs, mp.maxBytes)
	txids := make([][32]byte, 0, len(mp.txs))
	for txid := range mp.txs {
		txids = append(txids, txid)
	}
	sort.Slice(txids, func(i, j int) bool { return string(txids[i][:]) < string(txids[j][:]) })
	for _, txid := range txids {
		entry := mp.txs[txid]
		fmt.Fprintf(&out, " txkey=%x", txid)
		if entry == nil {
			out.WriteString(" nil")
			continue
		}
		fmt.Fprintf(&out, " raw=%x id=%x wid=%x tok=%p/%d fee=%d/%d weight=%d size=%d seq=%d src=%q", entry.raw, entry.txid, entry.wtxid, entry.token.owner, entry.token.seq, entry.fee.Hi, entry.fee.Lo, entry.weight, entry.size, entry.admissionSeq, entry.source)
		for _, input := range entry.inputs {
			fmt.Fprintf(&out, " in=%x/%d", input.Txid, input.Vout)
		}
	}
	wtxids := make([][32]byte, 0, len(mp.wtxids))
	for wtxid := range mp.wtxids {
		wtxids = append(wtxids, wtxid)
	}
	sort.Slice(wtxids, func(i, j int) bool { return string(wtxids[i][:]) < string(wtxids[j][:]) })
	for _, wtxid := range wtxids {
		fmt.Fprintf(&out, " wkey=%x->%x", wtxid, mp.wtxids[wtxid])
	}
	if owner == nil {
		return out.String() + " owner=nil"
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	generation := owner.generation
	if generation < generationAdvance {
		t.Fatalf("generation=%d below expected advance=%d", generation, generationAdvance)
	}
	generation -= generationAdvance
	fmt.Fprintf(&out, " owner=%p transition=%v tip=%v/%d/%x high=%d/%d", owner, owner.inTransition, owner.stableTip.HasTip, owner.stableTip.Height, owner.stableTip.Hash, owner.tokenHighWater, generation)
	tokens := make([]PendingOutpointToken, 0, len(owner.byToken))
	for token := range owner.byToken {
		tokens = append(tokens, token)
	}
	sort.Slice(tokens, func(i, j int) bool {
		return fmt.Sprintf("%p/%020d", tokens[i].owner, tokens[i].seq) < fmt.Sprintf("%p/%020d", tokens[j].owner, tokens[j].seq)
	})
	for _, token := range tokens {
		claim := owner.byToken[token]
		fmt.Fprintf(&out, " tkey=%p/%d", token.owner, token.seq)
		if claim == nil {
			out.WriteString(" nil")
			continue
		}
		fmt.Fprintf(&out, " tok=%p/%d domain=%d id=%x gen=%d final=%v", claim.token.owner, claim.token.seq, claim.domain, claim.txid, claim.generation, claim.finalized)
		for _, input := range claim.inputs {
			fmt.Fprintf(&out, " in=%x/%d", input.Txid, input.Vout)
		}
	}
	outpoints := make([]consensus.Outpoint, 0, len(owner.byOutpoint))
	for outpoint := range owner.byOutpoint {
		outpoints = append(outpoints, outpoint)
	}
	sort.Slice(outpoints, func(i, j int) bool {
		if txids := string(outpoints[i].Txid[:]); txids != string(outpoints[j].Txid[:]) {
			return txids < string(outpoints[j].Txid[:])
		}
		return outpoints[i].Vout < outpoints[j].Vout
	})
	for _, outpoint := range outpoints {
		row := owner.byOutpoint[outpoint]
		fmt.Fprintf(&out, " okey=%x/%d->%p/%d/%x", outpoint.Txid, outpoint.Vout, row.token.owner, row.token.seq, row.txid)
	}
	return out.String()
}
