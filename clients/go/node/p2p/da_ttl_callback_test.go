package p2p

import (
	"bytes"
	"context"
	"crypto/sha3"
	"errors"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// selectionProbe applies ACCEPTED/NEW blocks through SyncEngine.ApplyBlock and probes the retention of its commit.
type selectionProbe struct {
	t      *testing.T
	h      *testHarness
	source *testHarness
	f      *daIngressFixture
	commit []byte
	next   uint64
}

func newSelectionProbe(t *testing.T, h *testHarness, source *testHarness, id byte) *selectionProbe {
	t.Helper()
	f := newDAIngressFixture(t, h)
	commit := f.commit(daRelayTestID(id), 2)
	must(t, daRelayTestPeer(h, "127.0.0.1:19111", "127.0.0.1:19111").handleTx(commit), "retain the commit")
	return &selectionProbe{t: t, h: h, source: source, f: f, commit: commit, next: h.chainState.Height + 1}
}

// newSourceAndProbe builds a source chain of the given height, a one-block sink and its probe.
func newSourceAndProbe(t *testing.T, blocks int, id byte) (*testHarness, *testHarness, *selectionProbe) {
	t.Helper()
	source := newTestHarness(t, blocks, "127.0.0.1:0", nil)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	return source, h, newSelectionProbe(t, h, source, id)
}

// apply publishes the next source block through SyncEngine.ApplyBlock and requires ACCEPTED/NEW.
func (p *selectionProbe) apply() {
	p.t.Helper()
	summary, err := p.h.syncEngine.ApplyBlock(blockAtHeight(p.t, p.source, p.next), nil)
	require(p.t, err == nil && summary != nil && summary.BlockHeight == p.next, "ApplyBlock(%d)=(%+v,%v), want ACCEPTED/NEW", p.next, summary, err)
	p.next++
}

func newBoundService(t *testing.T, cfg ServiceConfig) *Service {
	t.Helper()
	service, err := NewService(cfg)
	require(t, err == nil && service != nil, "NewService: %v", err)
	t.Cleanup(func() { _, exit := startClose(service); joinWithin(t, "Close in cleanup", exit) })
	return service
}

// goDone runs fn on a new goroutine and returns a channel closed after fn returns or unwinds.
func goDone(fn func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return done
}

// joinWithin reports whether done closed within the lifecycle watchdog (nil skipped); a timeout goes to t.Errorf.
func joinWithin(t *testing.T, label string, done ...<-chan struct{}) bool {
	t.Helper()
	deadline := time.After(lifecycleWatchdog)
	for _, d := range done {
		if d == nil {
			continue
		}
		select {
		case <-d:
		case <-deadline:
			t.Errorf("%s did not return within %s", label, lifecycleWatchdog)
			return false
		}
	}
	return true
}

// requireJoined is joinWithin that stops the test while a listed goroutine is still running.
func requireJoined(t *testing.T, label string, done ...<-chan struct{}) {
	t.Helper()
	if !joinWithin(t, label, done...) {
		t.FailNow()
	}
}

// startClose runs s.Close on a new goroutine and returns its result and the goroutine's completion channel.
func startClose(s *Service) (<-chan error, <-chan struct{}) {
	closed := make(chan error, 1)
	return closed, goDone(func() { closed <- s.Close() })
}

// pollUntil reports whether cond held before the lifecycle watchdog passed; it does not stop the test.
func pollUntil(cond func() bool) bool {
	for deadline := time.Now().Add(lifecycleWatchdog); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			return false
		}
	}
	return true
}

// holdWorkLease registers a work lease on s and returns its release, which runs once, by the test or its cleanup.
func holdWorkLease(t *testing.T, s *Service) func() {
	t.Helper()
	require(t, s.acquireWork(), "work lease")
	var once sync.Once
	release := func() { once.Do(s.releaseWork) }
	t.Cleanup(release)
	return release
}

// TestDATTLCallbackServiceBinding: through SyncEngine.ApplyBlock over Services on one engine, S1's wrapped entry gets no attempt once S2 is bound, the identity read names S2, then S3 after Close(S3), then S4 after Close(S1), and the commit is retained after the third publication and absent after the fourth.
func TestDATTLCallbackServiceBinding(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xe1)
	engine, s1 := h.syncEngine, h.service
	require(t, engine.DATTLBindingService() == node.DATTLMutationService(s1), "identity read after S1 construction")
	w1 := &wrappedTTLEntry{inner: s1}
	engine.PublishDATTLBinding(w1)
	s2 := newBoundService(t, h.service.cfg)
	require(t, s2.daRelay == s1.daRelay && engine.DATTLBindingService() == node.DATTLMutationService(s2), "identity read after S2 construction")
	probe.apply()
	require(t, w1.attempts.Load() == 0, "S1 recorded %d entry attempts after S2 bound, want 0", w1.attempts.Load())
	s3 := newBoundService(t, h.service.cfg)
	require(t, s3.Close() == nil && engine.DATTLBindingService() == node.DATTLMutationService(s3), "Close(S3) cleared or replaced the binding")
	probe.apply()
	s4 := newBoundService(t, h.service.cfg)
	require(t, s1.Close() == nil && engine.DATTLBindingService() == node.DATTLMutationService(s4), "S4 binding")
	probe.apply()
	probe.f.requireRetained(probe.commit, "retained after the third publication, with S2, the CLOSED S3 and S4 bound in turn")
	probe.apply()
	probe.f.requireAbsent(probe.commit, "absent after the fourth publication")
}

// TestDATTLCallbackServiceConstructionFailure: failed constructions leave the binding naming S1, and the commit retained after the second publication is absent after the third.
func TestDATTLCallbackServiceConstructionFailure(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xe2)
	probe.apply()
	probe.apply()
	probe.f.requireRetained(probe.commit, "retained after the second publication")
	for _, row := range []struct {
		name   string
		mutate func(*ServiceConfig)
	}{
		{"validateServiceConfig", func(cfg *ServiceConfig) { cfg.BindAddr = "" }},
		{"newInboundBlockBudget", func(cfg *ServiceConfig) { cfg.InboundBlockBudgetBytes = maxInboundBlockBudgetBytes + 1 }},
	} {
		cfg := h.service.cfg
		row.mutate(&cfg)
		service, err := NewService(cfg)
		require(t, service == nil && err != nil, "%s: construction=(%p,%v)", row.name, service, err)
		require(t, h.syncEngine.DATTLBindingService() == node.DATTLMutationService(h.service), "%s: failed construction moved the binding", row.name)
	}
	probe.apply()
	probe.f.requireAbsent(probe.commit, "absent after the third publication, with the binding still naming S1")
}

// TestDATTLCallbackServiceConcurrentConstruction: two constructions race three publications under -race; the commit is retained after the second and absent after the third, and the final binding is one of the two constructions.
func TestDATTLCallbackServiceConcurrentConstruction(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xe3)
	type construction struct {
		service *Service
		err     error
	}
	built := make(chan construction, 2)
	start := make(chan struct{})
	var racing []<-chan struct{}
	for range 2 {
		racing = append(racing, goDone(func() {
			<-start
			service, err := NewService(h.service.cfg)
			built <- construction{service, err}
		}))
	}
	defer joinWithin(t, "the racing constructions", racing...)
	close(start)
	probe.apply()
	probe.apply()
	probe.f.requireRetained(probe.commit, "retained after the second publication")
	probe.apply()
	requireJoined(t, "the racing constructions", racing...)
	close(built)
	probe.f.requireAbsent(probe.commit, "absent after the third publication")
	services := map[node.DATTLMutationService]bool{}
	for c := range built {
		require(t, c.err == nil && c.service != nil, "NewService: %v", c.err)
		services[c.service] = true
		t.Cleanup(func() { _, exit := startClose(c.service); joinWithin(t, "Close in cleanup", exit) })
	}
	require(t, len(services) == 2 && services[h.syncEngine.DATTLBindingService()], "final binding outside the racing constructions")
}

// detachedReorgFixture is a sink tip block with one DA commit and chunk and a longer source branch to reorganize onto.
type detachedReorgFixture struct {
	commitRaw, chunkRaw []byte
	oldTip              [32]byte
	branch              [][]byte
}

// mineDetachedReorgFixture applies the common chain to sink, runs beforeOld, applies the sink DA block and mines branchLen unapplied source blocks; with spendChunkInput the first one spends the chunk's input, so the requeue retains only the commit.
func mineDetachedReorgFixture(t *testing.T, source, sink *testHarness, branchLen int, spendChunkInput bool, beforeOld func()) detachedReorgFixture {
	t.Helper()
	signer := mustP2PMLDSA87Keypair(t)
	mineAddress, timestamp := consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes()), uint64(1_778_000_000)
	minerConfig := func(provider node.CompleteDASetProvider, offset uint64) node.MinerConfig {
		cfg := node.DefaultMinerConfig()
		cfg.MineAddress = append([]byte(nil), mineAddress...)
		cfg.CompleteDASetProvider = provider
		cfg.TimestampSource = func() uint64 { timestamp += offset; return timestamp }
		return cfg
	}
	commonMiner, err := node.NewMiner(source.chainState, source.blockStore, source.syncEngine, minerConfig(nil, 1))
	must(t, err, "NewMiner(common)")
	spendable, spendValues := make([]consensus.Outpoint, 0, 2), make([]uint64, 0, 2)
	for height := uint64(1); height <= consensus.COINBASE_MATURITY+1; height++ {
		mined, err := commonMiner.MineOne(context.Background(), nil)
		must(t, err, fmt.Sprintf("MineOne(common %d)", height))
		block, err := source.blockStore.GetBlockByHash(mined.Hash)
		must(t, err, "GetBlockByHash(common)")
		if height <= 2 {
			parsed, err := consensus.ParseBlockBytes(block)
			must(t, err, "ParseBlockBytes(common)")
			coinbase, err := consensus.MarshalTx(parsed.Txs[0])
			must(t, err, "MarshalTx(coinbase)")
			_, txid, _, _, err := consensus.ParseTx(coinbase)
			must(t, err, "ParseTx(coinbase)")
			spendable = append(spendable, consensus.Outpoint{Txid: txid, Vout: 0})
			spendValues = append(spendValues, parsed.Txs[0].Outputs[0].Value)
		}
		_, err = sink.syncEngine.ApplyBlock(block, nil)
		must(t, err, fmt.Sprintf("apply common %d", height))
	}
	daID, payload := [32]byte{0xd7}, []byte("ttl binding detached reorg")
	commitment := sha3.Sum256(payload)
	commit := &consensus.Tx{
		Version: 1, TxKind: 0x01, TxNonce: 1,
		Inputs:       []consensus.TxInput{{PrevTxid: spendable[0].Txid, PrevVout: spendable[0].Vout}},
		Outputs:      []consensus.TxOutput{{CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: commitment[:]}},
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: 1, BatchNumber: 1},
	}
	chunk := &consensus.Tx{
		Version: 1, TxKind: 0x02, TxNonce: 2,
		Inputs:      []consensus.TxInput{{PrevTxid: spendable[1].Txid, PrevVout: spendable[1].Vout}},
		DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: 0, ChunkHash: commitment},
		DaPayload:   append([]byte(nil), payload...),
	}
	for _, tx := range []*consensus.Tx{commit, chunk} {
		must(t, consensus.SignTransaction(tx, sink.chainState.Utxos, node.DevnetGenesisChainID(), signer), "SignTransaction")
	}
	commitRaw, err := consensus.MarshalTx(commit)
	must(t, err, "MarshalTx(commit)")
	chunkRaw, err := consensus.MarshalTx(chunk)
	must(t, err, "MarshalTx(chunk)")
	provider := canonicalRelayDAProvider{{
		DAID: daID, PayloadBytes: uint64(len(payload)), CommitTx: commitRaw,
		Chunks: []node.CompleteDASetChunkCandidate{{Index: 0, Tx: chunkRaw}},
	}}
	beforeOld()
	oldMiner, err := node.NewMiner(sink.chainState, sink.blockStore, sink.syncEngine, minerConfig(provider, 1))
	must(t, err, "NewMiner(old)")
	old, err := oldMiner.MineOne(context.Background(), nil)
	must(t, err, "MineOne(old DA block)")
	branchMiner, err := node.NewMiner(source.chainState, source.blockStore, source.syncEngine, minerConfig(nil, 100))
	must(t, err, "NewMiner(branch)")
	fixture := detachedReorgFixture{commitRaw: commitRaw, chunkRaw: chunkRaw, oldTip: old.Hash}
	var conflict [][]byte
	if spendChunkInput {
		spend := &consensus.Tx{
			Version: 1, TxKind: 0x00, TxNonce: 3,
			Inputs:  []consensus.TxInput{{PrevTxid: spendable[1].Txid, PrevVout: spendable[1].Vout}},
			Outputs: []consensus.TxOutput{{Value: spendValues[1] - 1_000_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), mineAddress...)}},
		}
		must(t, consensus.SignTransaction(spend, source.chainState.Utxos, node.DevnetGenesisChainID(), signer), "SignTransaction(conflict)")
		raw, err := consensus.MarshalTx(spend)
		must(t, err, "MarshalTx(conflict)")
		conflict = [][]byte{raw}
	}
	for i := range branchLen {
		var txs [][]byte
		if i == 0 {
			txs = conflict
		}
		mined, err := branchMiner.MineOne(context.Background(), txs)
		must(t, err, fmt.Sprintf("MineOne(branch %d)", i))
		block, err := source.blockStore.GetBlockByHash(mined.Hash)
		must(t, err, "GetBlockByHash(branch)")
		fixture.branch = append(fixture.branch, block)
	}
	return fixture
}

// detachedReorgHookRetains reports whether a two-block reorganization retains the sink DA block's commit via the hook.
func detachedReorgHookRetains(t *testing.T, source, sink *testHarness) bool {
	t.Helper()
	fixture := mineDetachedReorgFixture(t, source, sink, 2, false, func() {})
	for i, block := range fixture.branch {
		_, err := sink.syncEngine.ApplyBlockWithReorg(block, nil)
		must(t, err, fmt.Sprintf("apply branch %d", i))
	}
	require(t, sink.chainState.TipHash == source.chainState.TipHash && sink.chainState.TipHash != fixture.oldTip, "reorganization did not move the sink tip")
	result, err := sink.syncEngine.DARelayState().AdmitDA(fixture.commitRaw, node.DetachedReorgDAProvenance())
	must(t, err, "retained commit probe")
	return result.Disposition == node.DAAdmissionDuplicate
}

// requireRetainedTx requires LookupRetainedTx to report raw's retention as want.
func requireRetainedTx(t *testing.T, h *testHarness, raw []byte, want bool, step string) {
	t.Helper()
	_, present, err := h.syncEngine.DARelayState().LookupRetainedTx(mustTxID(t, raw))
	require(t, err == nil && present == want, "%s: present=%v err=%v, want present=%v", step, present, err, want)
}

// TestDATTLCallbackEndToEndReorgRequeueNotDecreased: on a peer's lease path, a State B commit admitted before the sink DA block is retained after a winning reorganization and absent after the next publication, and the commit the reorganization requeues is retained after the next two publications and absent after the third.
func TestDATTLCallbackEndToEndReorgRequeueNotDecreased(t *testing.T) {
	source, sink := newTestHarness(t, 1, "127.0.0.1:0", nil), newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, sink)
	independent := f.commit(daRelayTestID(0xd9), 2)
	fixture := mineDetachedReorgFixture(t, source, sink, 5, true, func() { f.admit(independent, "127.0.0.1:19111") })
	p := testPeerForService(sink.service, "remote", 3)
	holdWorkLease(t, sink.service)
	relay := func(i int) {
		t.Helper()
		_, err := p.processRelayedBlock(fixture.branch[i])
		must(t, err, fmt.Sprintf("processRelayedBlock(branch %d)", i))
	}
	// Equal-work branch blocks may tie by hash, so the reorganization happens at the first relay that moves the tip.
	next := 0
	for sink.chainState.TipHash == fixture.oldTip {
		require(t, next < 2, "the branch did not win the reorganization")
		relay(next)
		next++
	}
	requireRetainedTx(t, sink, independent, true, "the State B commit retained after the reorganization")
	requireRetainedTx(t, sink, fixture.commitRaw, true, "the commit requeued by the reorganization")
	requireRetainedTx(t, sink, fixture.chunkRaw, false, "the chunk whose input the branch spent")
	relay(next)
	requireRetainedTx(t, sink, independent, false, "the State B commit absent after the first publication following the reorganization")
	relay(next + 1)
	requireRetainedTx(t, sink, fixture.commitRaw, true, "the requeued commit retained after the second publication following the reorganization")
	relay(next + 2)
	requireRetainedTx(t, sink, fixture.commitRaw, false, "the requeued commit absent after the third publication following the reorganization")
}

// TestDATTLCallbackLaterConstructionKeepsFirstHook: a later S2 becomes the binding while the detached-reorg hook stays with S1, so with S1 CLOSED the disconnected commit is not retained; with S1 OPEN it is.
func TestDATTLCallbackLaterConstructionKeepsFirstHook(t *testing.T) {
	for _, closeFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("first claimant closed=%v", closeFirst), func(t *testing.T) {
			source, sink := newTestHarness(t, 1, "127.0.0.1:0", nil), newTestHarness(t, 1, "127.0.0.1:0", nil)
			s2 := newBoundService(t, sink.service.cfg)
			require(t, s2.daRelay == sink.service.daRelay && sink.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "S2 construction")
			if closeFirst {
				require(t, sink.service.Close() == nil, "Close(S1)")
			}
			retained := detachedReorgHookRetains(t, source, sink)
			require(t, retained == !closeFirst, "detached commit retained=%v with first claimant closed=%v", retained, closeFirst)
		})
	}
}

// daRelayPublicImage is the exported DA image: A/B/C member identities by txid, retained bytes and candidates.
type daRelayPublicImage struct {
	identities []node.CompactCandidateIdentity
	members    map[[32]byte][]byte
	complete   []node.CompleteDASetCandidate
}

func observeDARelayPublicImage(t *testing.T, h *testHarness) daRelayPublicImage {
	t.Helper()
	relay := h.syncEngine.DARelayState()
	identities, ok := relay.CompactDAIdentities(h.mempool)
	require(t, ok, "CompactDAIdentities refused the engine mempool")
	slices.SortFunc(identities, func(a, b node.CompactCandidateIdentity) int { return bytes.Compare(a.TxID[:], b.TxID[:]) })
	image := daRelayPublicImage{identities: identities, members: map[[32]byte][]byte{}, complete: relay.CompleteSetCandidates(math.MaxUint64)}
	for _, identity := range identities {
		member, present, err := relay.LookupRetainedTx(identity.TxID)
		require(t, err == nil && present, "LookupRetainedTx(%x): present=%v err=%v", identity.TxID[:4], present, err)
		image.members[identity.TxID] = member.TxBytes
	}
	return image
}

// TestDATTLCallbackLaterConstructionKeepsPublicDAImage: a later NewService leaves the exported DA relay image unchanged.
func TestDATTLCallbackLaterConstructionKeepsPublicDAImage(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	f.admit(f.chunk(daRelayTestID(0xa8), 0, []byte("ttl nochg chunk")), "127.0.0.1:19111")
	f.admit(f.commit(daRelayTestID(0xb8), 2), "127.0.0.1:19112")
	before := observeDARelayPublicImage(t, h)
	require(t, len(before.identities) == 2 && len(before.members) == 2, "populated image: %d identities", len(before.identities))
	s2 := newBoundService(t, h.service.cfg)
	require(t, s2.daRelay == h.service.daRelay && h.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "S2 construction")
	require(t, reflect.DeepEqual(before, observeDARelayPublicImage(t, h)), "later construction changed the DA relay image")
}

// newEngineMiner mines one block on h's engine through node.Miner.MineOne, requires it as the tip and returns its bytes.
func newEngineMiner(t *testing.T, h *testHarness) func() []byte {
	t.Helper()
	cfg := node.DefaultMinerConfig()
	cfg.MineAddress = consensus.P2PKCovenantDataForPubkey(mustP2PMLDSA87Keypair(t).PubkeyBytes())
	timestamp := uint64(1_778_000_000)
	cfg.TimestampSource = func() uint64 { timestamp++; return timestamp }
	miner, err := node.NewMiner(h.chainState, h.blockStore, h.syncEngine, cfg)
	must(t, err, "NewMiner")
	return func() []byte {
		t.Helper()
		height := h.chainState.Height + 1
		mined, err := miner.MineOne(context.Background(), nil)
		must(t, err, fmt.Sprintf("MineOne(%d)", height))
		require(t, mined.Height == height && h.chainState.TipHash == mined.Hash, "mined block at %d is not the tip at %d", mined.Height, height)
		block, err := h.blockStore.GetBlockByHash(mined.Hash)
		must(t, err, "GetBlockByHash(mined)")
		return block
	}
}

// TestDATTLCallbackEndToEndSelection: across mined blocks, S1's retained AnnounceBlock, Close(S1) and S2's binding, three probed records are retained or absent after the listed blocks, and S1's AnnounceBlock returns "service already closed" once S1 is closed.
func TestDATTLCallbackEndToEndSelection(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	probe := newSelectionProbe(t, h, nil, 0xd1)
	mine := newEngineMiner(t, h)
	rpcAnnounce := h.service.AnnounceBlock
	p, f := probe.commit, probe.f
	must(t, rpcAnnounce(mine()), "AnnounceBlock of mined block 1")
	b2 := mine()
	f.requireRetained(p, "retained after mined block 2 and the AnnounceBlock of mined block 1")
	must(t, rpcAnnounce(b2), "AnnounceBlock of mined block 2")
	f.requireRetained(p, "retained after the AnnounceBlock of mined block 2")
	second := f.commit(daRelayTestID(0xd6), 2)
	f.admit(second, "127.0.0.1:19112")
	mine()
	f.requireAbsent(p, "absent after mined block 3")
	third := f.commit(daRelayTestID(0xd7), 2)
	f.admit(third, "127.0.0.1:19113")
	mine()
	f.requireRetained(second, "retained after mined blocks 3 and 4")
	must(t, h.service.Close(), "Close(S1)")
	mine()
	f.requireRetained(second, "retained after mined block 5, mined after Close(S1)")
	s2 := newBoundService(t, h.service.cfg)
	require(t, h.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "S2 binding")
	b6 := mine()
	f.requireAbsent(second, "absent after mined block 6")
	f.requireRetained(third, "retained after mined block 6")
	requireClosedRejection(t, rpcAnnounce(b6), "the closed S1's retained AnnounceBlock of mined block 6")
	f.requireRetained(third, "retained after the closed AnnounceBlock of mined block 6")
	mine()
	f.requireAbsent(third, "absent after mined block 7")
}

// TestDATTLCallbackEndToEndLeasePath: on a peer's lease path, State B Y and State A X are retained after their second relayed publication and absent, with their claims released, after their third; State C Z stays byte-equal and the binding's other OPEN Service S2 records zero entry attempts.
func TestDATTLCallbackEndToEndLeasePath(t *testing.T) {
	source, h, probe := newSourceAndProbe(t, 5, 0xd2)
	s2 := &wrappedTTLEntry{inner: newBoundService(t, h.service.cfg)}
	h.syncEngine.PublishDATTLBinding(s2)
	p := testPeerForService(h.service, "remote", 3)
	holdWorkLease(t, h.service)
	relayAccepted(t, p, source, 1)
	stateA := probe.f.chunk(daRelayTestID(0xa2), 0, []byte("lease-x"))
	probe.f.admit(stateA, "lease-a")
	zID, zCommitment := daRelayTestID(0xc2), sha3.Sum256([]byte("lease-z"))
	stateC := [][]byte{probe.f.tx(daTxSpec{kind: 0x01, daID: zID, chunkCount: 1, commitment: [][]byte{zCommitment[:]}}), probe.f.chunk(zID, 0, []byte("lease-z"))}
	probe.f.admit(stateC[0], "lease-c")
	probe.f.admit(stateC[1], "lease-c")
	spendOf := func(raw []byte, nonce uint64) []byte {
		in := mustParseP2PTx(t, raw).Inputs[0]
		return mustBuildSignedP2PTx(t, h.chainState.Utxos, []consensus.Outpoint{{Txid: in.PrevTxid, Vout: in.PrevVout}}, 100_000, 100_000, nonce, probe.f.signer, probe.f.address, probe.f.address)
	}
	var conflict *node.TxAdmitError
	requireClaimed := func(spend []byte, label string) {
		require(t, errors.As(h.mempool.AddTx(spend), &conflict) && conflict.Kind == node.TxAdmitConflict, "%s: want TxAdmitConflict", label)
	}
	requireExpired := func(raw, spend []byte, label string) {
		must(t, h.mempool.AddTx(spend), label+": a spend of its input after the expiry released its claim")
		_, err := probe.f.probe(raw)
		require(t, errors.As(err, &conflict) && conflict.Kind == node.TxAdmitConflict, "%s after its expiry: probe err=%v, want the conflict of an absent member, not its DUPLICATE", label, err)
	}
	requireZ := func(step string) {
		for _, raw := range stateC {
			member, present, err := h.syncEngine.DARelayState().LookupRetainedTx(mustTxID(t, raw))
			require(t, err == nil && present && bytes.Equal(member.TxBytes, raw), "%s: Z member present=%v err=%v, want its unchanged bytes", step, present, err)
		}
	}
	spendY, spendX := spendOf(probe.commit, 9581), spendOf(stateA, 9582)
	relayAccepted(t, p, source, 2)
	probe.f.requireRetained(probe.commit, "Y retained after its second publication")
	requireClaimed(spendY, "a spend of Y's input while Y holds its claim")
	requireZ("before the apply")
	relayAccepted(t, p, source, 3)
	requireExpired(probe.commit, spendY, "Y")
	probe.f.requireRetained(stateA, "X retained after its second publication")
	requireZ("after the apply")
	requireClaimed(spendX, "a spend of X's input while X holds its claim")
	relayAccepted(t, p, source, 4)
	requireExpired(stateA, spendX, "X")
	requireZ("after a State A record expires")
	require(t, s2.attempts.Load() == 0, "the OPEN bound S2 recorded %d entry attempts, want 0", s2.attempts.Load())
}

// TestDATTLCallbackServiceEntryErrorReleasesLease: EnterDATTLMutation called directly returns the decrease's error and releases the lease Close awaits.
func TestDATTLCallbackServiceEntryErrorReleasesLease(t *testing.T) {
	h, refusal := newTestHarness(t, 0, "127.0.0.1:0", nil), errors.New("decrease refusal")
	var closed <-chan error
	var closeDone <-chan struct{}
	defer func() { joinWithin(t, "Close", closeDone) }()
	calls := 0
	got := h.service.EnterDATTLMutation(func() error {
		calls++
		closed, closeDone = startClose(h.service)
		waitDraining(t, h.service)
		requireStillBlocked(t, closed, "Close while the registered decrease runs")
		return refusal
	})
	require(t, errors.Is(got, refusal) && reflect.TypeOf(got) == reflect.TypeOf(refusal) && calls == 1, "entry=%v after %d decrease calls, want the decrease's own error value after 1", got, calls)
	requireReturned(t, closed, "Close after the entry released its lease")
}

// TestDATTLCallbackServiceEntryPanicWhileCloseWaits: a decrease passed directly to EnterDATTLMutation panics while Close waits on the entry's lease; the panic propagates unrecovered, the lease is released once and Close returns (RUBIN_L1_P2P_AUX.md Section 5).
func TestDATTLCallbackServiceEntryPanicWhileCloseWaits(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	entered, unwind := make(chan struct{}), make(chan struct{})
	var unwindOnce sync.Once
	release := func() { unwindOnce.Do(func() { close(unwind) }) }
	var got any
	exited := make(chan error, 1)
	worker := goDone(func() {
		defer func() { got = recover(); exited <- nil }()
		_ = h.service.EnterDATTLMutation(func() error { close(entered); <-unwind; panic("decrease panic") })
	})
	var closeDone <-chan struct{}
	defer func() {
		release()
		joinWithin(t, "the panicking entry and the waiting Close", worker, closeDone)
	}()
	select {
	case <-entered:
	case <-exited:
		t.Fatalf("EnterDATTLMutation returned (%v) without invoking the decrease", got)
	case <-time.After(lifecycleWatchdog):
		t.Fatalf("the decrease was not invoked within %s", lifecycleWatchdog)
	}
	var closed <-chan error
	closed, closeDone = startClose(h.service)
	waitDraining(t, h.service)
	requireStillBlocked(t, closed, "Close")
	release()
	requireReturned(t, exited, "the panicking entry after the release")
	require(t, got == "decrease panic", "panic value, want the original propagated unrecovered")
	requireReturned(t, closed, "the waiting Close after the panicking entry")
}

// mineSideBlock mines a height-1 block on a fresh chain, a valid lower-work side-branch block for a height-2 node.
func mineSideBlock(t *testing.T) []byte {
	t.Helper()
	fork := newTestHarness(t, 1, "127.0.0.1:0", nil)
	cfg := node.DefaultMinerConfig()
	cfg.MineAddress = consensus.P2PKCovenantDataForPubkey(mustP2PMLDSA87Keypair(t).PubkeyBytes())
	miner, err := node.NewMiner(fork.chainState, fork.blockStore, fork.syncEngine, cfg)
	must(t, err, "NewMiner(side)")
	mined, err := miner.MineOne(context.Background(), nil)
	must(t, err, "MineOne(side)")
	block, err := fork.blockStore.GetBlockByHash(mined.Hash)
	must(t, err, "GetBlockByHash(side)")
	return block
}

// newSideBlockSetup retains the probe commit and a State A chunk, relays heights 1 and 2 through p under a held work lease, requires both retained, and returns the chunk and a side-branch block h does not know.
func newSideBlockSetup(t *testing.T, id byte) (*testHarness, *testHarness, *peer, *selectionProbe, []byte, []byte, [32]byte) {
	t.Helper()
	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	sideBlock := mineSideBlock(t)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	probe := newSelectionProbe(t, h, source, id)
	x := probe.f.chunk(daRelayTestID(id^0x80), 0, []byte("side-block x"))
	probe.f.admit(x, "side-a")
	p := testPeerForService(h.service, "remote", 5)
	holdWorkLease(t, h.service)
	relayAccepted(t, p, source, 1)
	relayAccepted(t, p, source, 2)
	probe.f.requireRetained(x, "the State A chunk retained after two publications")
	probe.f.requireRetained(probe.commit, "the State B commit retained after two publications")
	sideHash, err := consensus.BlockHash(sideBlock[:consensus.BLOCK_HEADER_BYTES])
	must(t, err, "BlockHash(side block)")
	known, err := h.service.hasBlock(sideHash)
	require(t, err == nil && !known, "the side block is already known: err=%v", err)
	return source, h, p, probe, x, sideBlock, sideHash
}

// relayAccepted relays source's block at height through p and requires an applied summary.
func relayAccepted(t *testing.T, p *peer, source *testHarness, height uint64) {
	t.Helper()
	summary, err := p.processRelayedBlock(blockAtHeight(t, source, height))
	require(t, err == nil && summary != nil, "processRelayedBlock(%d)=(%+v,%v)", height, summary, err)
}

// TestDATTLCallbackEndToEndNonAcceptedResults: after a stored side block, KNOWN_BLOCK_NOOP, MISSING_PARENT and CONSENSUS_INVALID both probed records are retained with no binding entry attempt, relayed block 3 leaves them absent, DisconnectTip makes no entry attempt, and a later record is retained after block 3, DisconnectTip and the reconnect and absent after block 4.
func TestDATTLCallbackEndToEndNonAcceptedResults(t *testing.T) {
	source, h, p, probe, x, sideBlock, _ := newSideBlockSetup(t, 0xd3)
	entry := &wrappedTTLEntry{inner: h.service}
	h.syncEngine.PublishDATTLBinding(entry)
	summary, err := h.syncEngine.ApplyBlockWithReorg(sideBlock, nil)
	require(t, err == nil && summary != nil && len(summary.CanonicalAppliedBlocks) == 0 && h.chainState.Height == 2, "side block=(%+v,%v) height=%d, want stored non-canonical", summary, err, h.chainState.Height)
	probe.f.requireRetained(x, "the State A chunk retained after the stored side block")
	summary, err = p.processRelayedBlock(blockAtHeight(t, source, 2))
	require(t, err == nil && summary == nil, "known block replay=(%+v,%v), want KNOWN_BLOCK_NOOP", summary, err)
	summary, err = p.processRelayedBlock(blockAtHeight(t, source, 5))
	require(t, err == nil && summary == nil && h.service.orphans.Len() == 1, "missing parent=(%+v,%v) orphans=%d, want one retained orphan", summary, err, h.service.orphans.Len())
	invalid := append([]byte(nil), blockAtHeight(t, source, 3)...)
	invalid[4+32] ^= 0xff // the merkle root
	summary, err = testPeerForService(h.service, "invalid", 5).processRelayedBlock(invalid)
	var invalidErr *consensus.TxError
	require(t, errors.As(err, &invalidErr) && invalidErr.Code == consensus.BLOCK_ERR_MERKLE_INVALID && summary == nil && h.chainState.Height == 2, "invalid block=(%+v,%v), want BLOCK_ERR_MERKLE_INVALID", summary, err)
	probe.f.requireRetained(x, "the State A chunk retained after the replay, the orphan and the invalid block")
	probe.f.requireRetained(probe.commit, "the State B commit retained after the side block, the replay, the orphan and the invalid block")
	require(t, entry.attempts.Load() == 0, "entry attempts=%d after the direct side block, want 0", entry.attempts.Load())
	fresh := probe.f.commit(daRelayTestID(0xd8), 2)
	probe.f.admit(fresh, "127.0.0.1:19112")
	relayAccepted(t, p, source, 3)
	probe.f.requireAbsent(x, "the State A chunk absent after relayed block 3")
	probe.f.requireAbsent(probe.commit, "the State B commit absent after relayed block 3")
	disconnected, err := h.syncEngine.DisconnectTip()
	require(t, err == nil && disconnected != nil && h.chainState.Height == 2, "DisconnectTip=(%+v,%v)", disconnected, err)
	require(t, entry.attempts.Load() == 0, "entry attempts=%d before the reconnect, want 0", entry.attempts.Load())
	reconnected, err := h.syncEngine.ApplyBlock(blockAtHeight(t, source, 3), nil)
	require(t, err == nil && reconnected != nil, "reconnect(3)=(%+v,%v)", reconnected, err)
	probe.f.requireRetained(fresh, "retained after relayed block 3, DisconnectTip and the reconnect")
	relayAccepted(t, p, source, 4)
	probe.f.requireAbsent(fresh, "absent after relayed block 4")
}

// TestDATTLCallbackEndToEndStoredSideBlockThroughPeer: a side-branch block a peer relays is stored non-canonical with no binding entry attempt, a State A chunk retained after two publications is still retained after it, and relayed block 3 leaves the chunk and the commit absent.
func TestDATTLCallbackEndToEndStoredSideBlockThroughPeer(t *testing.T) {
	source, h, p, probe, x, sideBlock, sideHash := newSideBlockSetup(t, 0xd4)
	entry := &wrappedTTLEntry{inner: h.service}
	h.syncEngine.PublishDATTLBinding(entry)
	_, err := p.processRelayedBlock(sideBlock)
	must(t, err, "processRelayedBlock(side block)")
	stored, err := h.blockStore.GetBlockByHash(sideHash)
	require(t, err == nil && bytes.Equal(stored, sideBlock) && h.chainState.Height == 2 && h.chainState.TipHash != sideHash, "side block stored=%v err=%v height=%d, want stored non-canonical", stored != nil, err, h.chainState.Height)
	probe.f.requireRetained(x, "the State A chunk retained after the stored side block")
	require(t, entry.attempts.Load() == 0, "binding entry attempts=%d, want 0", entry.attempts.Load())
	relayAccepted(t, p, source, 3)
	probe.f.requireAbsent(x, "the State A chunk absent after relayed block 3")
	probe.f.requireAbsent(probe.commit, "the State B commit absent after relayed block 3")
}

// TestDATTLCallbackEndToEndDrainingBindingRefused: the DRAINING current binding S2 refuses a direct EnterDATTLMutation with errServiceClosed without running the decrease, the commit is retained after the publication under it, Close(S2) waits for the held lease, and after a fresh construction the next publication leaves the commit absent.
func TestDATTLCallbackEndToEndDrainingBindingRefused(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xd5)
	probe.apply()
	probe.apply()
	s2 := newBoundService(t, h.service.cfg)
	requireEntryRefused := func(label string) {
		t.Helper()
		err := s2.EnterDATTLMutation(func() error { t.Errorf("%s: the refused registration ran the decrease", label); return nil })
		requireClosedRejection(t, err, label)
		require(t, errors.Is(err, errServiceClosed) && reflect.TypeOf(err) == reflect.TypeOf(errServiceClosed), "%s: err=%v, want errServiceClosed", label, err)
	}
	release := holdWorkLease(t, s2)
	closeDone, closeExit := startClose(s2)
	defer func() { release(); joinWithin(t, "Close(S2)", closeExit) }()
	waitDraining(t, s2)
	requireEntryRefused("EnterDATTLMutation(S2) while DRAINING")
	probe.apply()
	probe.f.requireRetained(probe.commit, "retained after the third publication, the one under the DRAINING binding S2")
	requireStillBlocked(t, closeDone, "Close(S2)")
	release()
	requireReturned(t, closeDone, "Close(S2) after the release")
	requireEntryRefused("EnterDATTLMutation(S2) after Close returned")
	require(t, h.service.workAuthorized() && h.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "S1 left OPEN and the binding kept naming S2")
	newBoundService(t, h.service.cfg)
	probe.apply()
	probe.f.requireAbsent(probe.commit, "absent after the fourth publication, the first after a fresh construction")
}

// wrappedTTLEntry adds one to attempts per call, runs before, when set, and enters inner.
type wrappedTTLEntry struct {
	inner    *Service
	before   func()
	attempts atomic.Int64
}

func (w *wrappedTTLEntry) EnterDATTLMutation(decrease func() error) error {
	w.attempts.Add(1)
	if w.before != nil {
		w.before()
	}
	return w.inner.EnterDATTLMutation(decrease)
}

// goroutineParked reports whether one goroutine's stack dump contains the given fragments.
func goroutineParked(fragments ...string) bool {
	stack := make([]byte, 1<<22)
	return slices.ContainsFunc(strings.Split(string(stack[:runtime.Stack(stack, true)]), "\n\n"), func(g string) bool {
		return !slices.ContainsFunc(fragments, func(f string) bool { return !strings.Contains(g, f) })
	})
}

// TestDATTLCallbackEndToEndEntryInsideTheHold: a ReleasePeerQuotaKey and a DA admission started inside the entry park on the admission guard until it is released (RUBIN_COMPACT_BLOCKS.md Section 5).
func TestDATTLCallbackEndToEndEntryInsideTheHold(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xe5)
	fresh := probe.f.chunk(daRelayTestID(0xe7), 0, []byte("in-hold"))
	done := make(chan error, 2)
	var writers []<-chan struct{}
	defer func() { joinWithin(t, "the parked writers", writers...) }()
	var notParked []string
	park := func(frame string, write func() error) {
		writers = append(writers, goDone(func() { done <- write() }))
		if !pollUntil(func() bool { return goroutineParked("RLockUnlessTerminal", "sync.(*Cond).Wait", frame) }) {
			notParked = append(notParked, frame)
		}
	}
	entry := &wrappedTTLEntry{inner: h.service}
	entry.before = func() {
		entry.before = nil
		park("ReleasePeerQuotaKey", func() error { return h.syncEngine.DARelayState().ReleasePeerQuotaKey("unrelated-peer") })
		park("AdmitDA", func() error { return probe.f.tryAdmit(fresh, "in-hold-peer") })
	}
	h.syncEngine.PublishDATTLBinding(entry)
	probe.apply()
	require(t, entry.attempts.Load() == 1, "entry attempts=%d, want 1", entry.attempts.Load())
	requireJoined(t, "the parked writers after the guard release", writers...)
	require(t, len(notParked) == 0, "%v did not park on the admission guard before the watchdog", notParked)
	for range writers {
		must(t, <-done, "parked writer after the guard release")
	}
	probe.apply()
	probe.f.requireRetained(probe.commit, "retained after the second publication")
	probe.apply()
	probe.f.requireAbsent(probe.commit, "absent after the third publication")
	probe.f.requireRetained(fresh, "the record whose admission parked in the first publication's entry, retained after the third publication")
	probe.apply()
	probe.f.requireAbsent(fresh, "absent after the fourth publication")
}

// TestDATTLCallbackEndToEndPreCommitLatchInvokesNothing: a transition latching before the commit makes no entry attempt.
func TestDATTLCallbackEndToEndPreCommitLatchInvokesNothing(t *testing.T) {
	source := newTestHarness(t, 4, "127.0.0.1:0", nil)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	entry := &wrappedTTLEntry{inner: h.service}
	h.syncEngine.PublishDATTLBinding(entry)
	latchDAHarness(t, h, source)
	require(t, entry.attempts.Load() == 0, "pre-commit latch entry attempts=%d, want 0", entry.attempts.Load())
}

// TestDATTLCallbackEndToEndDrainingLease: while S is DRAINING, its worker's block message applies ACCEPTED/NEW with one binding entry attempt in total, the commit is absent and a later record retained after it, and Close(S) returns only after the worker's lease is released.
func TestDATTLCallbackEndToEndDrainingLease(t *testing.T) {
	source, h, probe := newSourceAndProbe(t, 6, 0xe7)
	probe.apply()
	second := probe.f.commit(daRelayTestID(0xe4), 2)
	probe.f.admit(second, "127.0.0.1:19112")
	s2 := &wrappedTTLEntry{inner: newBoundService(t, h.service.cfg)}
	p := testPeerForService(h.service, "remote", 5)
	release := holdWorkLease(t, h.service)
	block := blockAtHeight(t, source, probe.next+1)
	var summary *node.ChainStateConnectSummary
	var relayErr error
	var worker, closeExit <-chan struct{}
	var closeDone <-chan error
	defer func() { release(); joinWithin(t, "the worker's block message and Close(S)", worker, closeExit) }()
	var missed []string
	s2.before = func() {
		s2.before = nil
		worker = goDone(func() { summary, relayErr = p.processRelayedBlock(block) })
		if !pollUntil(func() bool {
			return goroutineParked("[sync.Mutex.Lock", "ApplyBlockWithReorgDeferredUnderLease", "processRelayedBlock")
		}) {
			missed = append(missed, "the worker parked inside its block message")
		}
		closeDone, closeExit = startClose(h.service)
		if !pollUntil(func() bool { return !h.service.workAuthorized() }) {
			missed = append(missed, "Close(S) publishing DRAINING")
		}
	}
	h.syncEngine.PublishDATTLBinding(s2)
	probe.apply()
	requireJoined(t, "the worker's block message", worker)
	require(t, len(missed) == 0, "%v not observed before the watchdog", missed)
	require(t, relayErr == nil && summary != nil && summary.BlockHeight == probe.next, "processRelayedBlock=(%+v,%v), want ACCEPTED/NEW at %d", summary, relayErr, probe.next)
	probe.f.requireAbsent(probe.commit, "absent after the worker's publication")
	probe.f.requireRetained(second, "the later record retained after the worker's publication")
	require(t, s2.attempts.Load() == 1, "binding entry attempts=%d, want 1", s2.attempts.Load())
	requireStillBlocked(t, closeDone, "Close(S) while the worker's lease is held")
	release()
	requireReturned(t, closeDone, "Close(S) after the worker's lease is released")
	probe.next = summary.BlockHeight + 1
	probe.apply()
	probe.f.requireAbsent(second, "the later record absent after the next publication")
}

// TestDATTLCallbackEndToEndAbsentBinding: with no Service and no binding, a State A chunk is retained after three publications and after two more once a Service is constructed, and absent after the third publication after that construction.
func TestDATTLCallbackEndToEndAbsentBinding(t *testing.T) {
	source := newTestHarness(t, 7, "127.0.0.1:0", nil)
	sink, cfg := unclaimedServiceSink(t)
	require(t, sink.syncEngine.DATTLBindingService() == nil, "binding present with no constructed Service")
	sink.service = &Service{daRelay: sink.syncEngine.DARelayState()}
	f := newDAIngressFixture(t, sink)
	x := f.chunk(daRelayTestID(0xe8), 0, []byte("absent-binding x"))
	f.admit(x, "127.0.0.1:19111")
	apply := func(height uint64) {
		t.Helper()
		summary, err := sink.syncEngine.ApplyBlock(blockAtHeight(t, source, height), nil)
		require(t, err == nil && summary != nil && summary.BlockHeight == height, "ApplyBlock(%d)=(%+v,%v), want ACCEPTED/NEW", height, summary, err)
	}
	start := sink.chainState.Height + 1
	for height := start; height < start+3; height++ {
		apply(height)
	}
	require(t, sink.syncEngine.DATTLBindingService() == nil, "an apply published a binding")
	f.requireRetained(x, "the State A chunk after three publications under an absent binding")
	newBoundService(t, cfg)
	for height := start + 3; height < start+6; height++ {
		if apply(height); height == start+4 {
			f.requireRetained(x, "retained after the fifth publication, the second after NewService")
		}
	}
	f.requireAbsent(x, "absent after the sixth publication, the third after NewService")
}

// requireAbsentBindingDecreasesNothing: a commit is retained after three publications under no binding and two more after NewService(cfg) binds, and absent after the sixth; six DisconnectTip calls restore the tip; returns that Service.
func requireAbsentBindingDecreasesNothing(t *testing.T, sink *testHarness, cfg ServiceConfig) *Service {
	t.Helper()
	source := newTestHarness(t, int(sink.chainState.Height)+7, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, sink)
	commit := f.commit(daRelayTestID(0xe9), 2)
	f.admit(commit, "127.0.0.1:19111")
	start := sink.chainState.Height + 1
	apply := func(from, to uint64) {
		t.Helper()
		for height := from; height < to; height++ {
			summary, err := sink.syncEngine.ApplyBlock(blockAtHeight(t, source, height), nil)
			require(t, err == nil && summary != nil && summary.BlockHeight == height, "ApplyBlock(%d)=(%+v,%v), want ACCEPTED/NEW", height, summary, err)
		}
	}
	apply(start, start+3)
	require(t, sink.syncEngine.DATTLBindingService() == nil, "an apply published a binding")
	service, err := NewService(cfg)
	require(t, err == nil && sink.syncEngine.DATTLBindingService() == node.DATTLMutationService(service), "NewService after the absent-binding publications: %v", err)
	apply(start+3, start+5)
	f.requireRetained(commit, "retained after the fifth publication, the second under the bound Service")
	apply(start+5, start+6)
	f.requireAbsent(commit, "absent after the sixth publication, the third under the bound Service")
	for range 6 {
		_, err := sink.syncEngine.DisconnectTip()
		must(t, err, "DisconnectTip back to the starting tip")
	}
	require(t, sink.chainState.Height+1 == start, "tip height=%d after the disconnects, want %d", sink.chainState.Height, start-1)
	return service
}

// TestDATTLCallbackEndToEndSnapshotBeforePublication: S2 bound inside S1's entry gets no attempt from that publication; S1 gets one attempt and S2 the next two, and the commit is retained after the second publication and absent after the third.
func TestDATTLCallbackEndToEndSnapshotBeforePublication(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xea)
	s2 := &wrappedTTLEntry{inner: newBoundService(t, h.service.cfg)}
	var once sync.Once
	s1 := &wrappedTTLEntry{inner: h.service}
	s1.before = func() { once.Do(func() { h.syncEngine.PublishDATTLBinding(s2) }) }
	h.syncEngine.PublishDATTLBinding(s1)
	probe.apply()
	require(t, s1.attempts.Load() == 1 && s2.attempts.Load() == 0, "first publication attempts S1=%d S2=%d, want 1 and 0", s1.attempts.Load(), s2.attempts.Load())
	require(t, h.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "binding after the publication, want S2")
	probe.apply()
	probe.f.requireRetained(probe.commit, "retained after the second publication")
	probe.apply()
	require(t, s1.attempts.Load() == 1 && s2.attempts.Load() == 2, "attempts S1=%d S2=%d, want 1 and 2", s1.attempts.Load(), s2.attempts.Load())
	probe.f.requireAbsent(probe.commit, "absent after the third publication")
}

// TestDATTLCallbackEndToEndNoGuardReacquisition: three publications return within the watchdog; the first makes one entry attempt, and the commit is retained after the second and absent after the third.
func TestDATTLCallbackEndToEndNoGuardReacquisition(t *testing.T) {
	source, h, probe := newSourceAndProbe(t, 4, 0xeb)
	entry := &wrappedTTLEntry{inner: h.service}
	h.syncEngine.PublishDATTLBinding(entry)
	apply := func(height uint64, block []byte) {
		t.Helper()
		var summary *node.ChainStateConnectSummary
		var err error
		done := make(chan struct{})
		go func() { defer close(done); summary, err = h.syncEngine.ApplyBlock(block, nil) }()
		select {
		case <-done:
			require(t, err == nil && summary != nil && summary.BlockHeight == height, "ApplyBlock=(%+v,%v), want ACCEPTED/NEW at %d", summary, err, height)
		case <-time.After(lifecycleWatchdog):
			t.Fatalf("ApplyBlock(%d) did not return within %s: the TTL body waited for the held admission guard", height, lifecycleWatchdog)
		}
	}
	blocks := [][]byte{blockAtHeight(t, source, probe.next), blockAtHeight(t, source, probe.next+1), blockAtHeight(t, source, probe.next+2)}
	apply(probe.next, blocks[0])
	require(t, entry.attempts.Load() == 1, "entry attempts=%d, want 1", entry.attempts.Load())
	apply(probe.next+1, blocks[1])
	probe.f.requireRetained(probe.commit, "retained after the second publication")
	apply(probe.next+2, blocks[2])
	probe.f.requireAbsent(probe.commit, "absent after the third publication")
}

// closeRaceEntry wraps S1's entry; its one attempt starts the race and records S1's admission and Close(S1)'s return.
type closeRaceEntry struct {
	inner          *Service
	start          func(inside bool)
	closeReturned  *atomic.Bool
	attempts       int
	ran, afterExit bool
}

func (c *closeRaceEntry) EnterDATTLMutation(decrease func() error) error {
	c.attempts++
	c.start(false)
	return c.inner.EnterDATTLMutation(func() error {
		c.ran, c.afterExit = true, c.closeReturned.Load()
		c.start(true)
		return decrease()
	})
}

// TestDATTLCallbackEndToEndCloseRaceOutcomes: Close(S1) and S2's construction race S1's registration after its snapshot; S1's entry gets one attempt, does not run the decrease after Close(S1) returned, runs it in round 1 and not in even rounds, and the commit is retained after a round's second publication, after its third when S1 did not run the decrease, and absent after its last.
func TestDATTLCallbackEndToEndCloseRaceOutcomes(t *testing.T) {
	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	var racing []<-chan struct{}
	defer func() { joinWithin(t, "the racing Close(S1) and S2 construction", racing...) }()
	for i := range 8 {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		probe := newSelectionProbe(t, h, source, 0xec)
		probe.apply()
		var closeReturned atomic.Bool
		var s2 atomic.Pointer[Service]
		entry := &closeRaceEntry{inner: h.service, closeReturned: &closeReturned}
		entry.start = func(inside bool) {
			if inside != (i == 1) {
				return
			}
			racing = append(racing, goDone(func() { _ = h.service.Close(); closeReturned.Store(true) }), goDone(func() {
				if service, err := NewService(h.service.cfg); err == nil {
					s2.Store(service)
				}
			}))
			if inside {
				waitUntil(t, func() bool { return s2.Load() != nil }, "S2 bound while the decrease is held")
				waitDraining(t, h.service)
				waitUntil(t, func() bool {
					return closeReturned.Load() || goroutineParked("[sync.WaitGroup.Wait", "(*Service).Close", "TestDATTLCallbackEndToEndCloseRaceOutcomes")
				}, "Close(S1) parked on its work leases or returned")
				require(t, !closeReturned.Load(), "Close(S1) returned while its registered decrease ran")
			} else if i%2 == 0 {
				requireJoined(t, "the racing goroutines", racing...)
			}
		}
		h.syncEngine.PublishDATTLBinding(entry)
		probe.apply()
		requireJoined(t, "the racing goroutines", racing...)
		require(t, entry.attempts == 1 && !entry.afterExit, "round %d: attempts=%d decrease after Close returned=%v", i, entry.attempts, entry.afterExit)
		require(t, entry.ran == (i == 1) || i > 1 && i%2 == 1, "round %d: S1 admitted=%v, want admitted in round 1, where Close(S1) and S2 start inside the held decrease, and refused in even rounds, where both finish before the registration", i, entry.ran)
		probe.f.requireRetained(probe.commit, fmt.Sprintf("round %d: retained after the second publication", i))
		service := s2.Load()
		require(t, service != nil && h.syncEngine.DATTLBindingService() == node.DATTLMutationService(service), "round %d: S2 construction and binding", i)
		if !entry.ran {
			probe.apply()
			probe.f.requireRetained(probe.commit, fmt.Sprintf("round %d: retained after the third publication", i))
		}
		probe.apply()
		probe.f.requireAbsent(probe.commit, fmt.Sprintf("round %d: absent after the last publication", i))
		requireReturned(t, lifecycleClose(service), fmt.Sprintf("round %d: Close(S2)", i))
	}
}
