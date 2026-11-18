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

// selectionProbe observes the production no-lease selection: each step is one ACCEPTED/NEW SyncEngine.ApplyBlock
// publication, and the commit retained at count 3 counts admitted selections (count 1 after two, gone at third).
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
	must(t, daRelayTestPeer(h, "127.0.0.1:19111", "127.0.0.1:19111").handleTx(commit), "retain the commit at count 3")
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
	t.Cleanup(func() { _ = service.Close() })
	return service
}

// waitWithin bounds wg.Wait by the lifecycle watchdog.
func waitWithin(t *testing.T, wg *sync.WaitGroup, label string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { wg.Wait(); done <- nil }()
	requireReturned(t, done, label)
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

// TestDATTLCallbackServiceBinding drives the production no-lease selection through SyncEngine.ApplyBlock over real
// Services sharing one SyncEngine: with S1 and S2 OPEN the latest construction S2 admits the decrease; a CLOSED current
// binding S3 refuses with zero DA effects and nothing falls back to the OPEN S1 or S2; S4 after Close(S1) admits; and
// the identity read follows constructions and survives Close.
func TestDATTLCallbackServiceBinding(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xe1)
	engine, s1 := h.syncEngine, h.service
	require(t, engine.DATTLBindingService() == node.DATTLMutationService(s1), "identity read after S1 construction")
	w1 := &wrappedTTLEntry{inner: s1}
	engine.PublishDATTLBinding(w1)
	s2 := newBoundService(t, h.service.cfg)
	require(t, s2.daRelay == s1.daRelay && engine.DATTLBindingService() == node.DATTLMutationService(s2), "identity read after S2 construction")
	probe.apply()
	require(t, w1.attempts.Load() == 0, "S1 recorded %d registrations after S2 bound, want 0", w1.attempts.Load())
	s3 := newBoundService(t, h.service.cfg)
	require(t, s3.Close() == nil && engine.DATTLBindingService() == node.DATTLMutationService(s3), "Close(S3) cleared or replaced the binding")
	probe.apply()
	s4 := newBoundService(t, h.service.cfg)
	require(t, s1.Close() == nil && engine.DATTLBindingService() == node.DATTLMutationService(s4), "S4 binding")
	probe.apply()
	probe.f.requireRetained(probe.commit, "count 1: S2 and S4 admitted, the CLOSED S3 refused with no fallback")
	probe.apply()
	probe.f.requireAbsent(probe.commit, "the fourth publication's admitted decrease expired the record")
}

// TestDATTLCallbackServiceConstructionFailure drives the production selection: a construction failing at config
// validation or at the inbound budget leaves the binding naming S1, whose registration then admits the decrease of the
// next ACCEPTED/NEW publication. On an engine with no claim yet, every such refusal claims nothing, so the next
// successful construction is the first claimant: its admitDetachedReorgDA is the engine's detached-reorg hook.
func TestDATTLCallbackServiceConstructionFailure(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xe2)
	probe.apply()
	probe.apply()
	probe.f.requireRetained(probe.commit, "count 1 after two decreases admitted by S1")
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
	probe.f.requireAbsent(probe.commit, "S1, still bound after the failed constructions, admitted the decrease")
	for _, row := range []struct {
		want string
		bad  func(*ServiceConfig)
	}{
		{"bind address is required", func(c *ServiceConfig) { c.BindAddr = "" }},
		{"nil peer manager", func(c *ServiceConfig) { c.PeerManager = nil }},
		{"nil sync engine", func(c *ServiceConfig) { c.SyncEngine = nil }},
		{"nil blockstore", func(c *ServiceConfig) { c.BlockStore = nil }},
		{"nil tx metadata func", func(c *ServiceConfig) { c.TxMetadataFunc = nil }},
		{"inbound block budget must be zero or between 1073741824 and 8589934592 bytes", func(c *ServiceConfig) { c.InboundBlockBudgetBytes = 1073741823 }},
	} {
		t.Run("first claimant after "+row.want, func(t *testing.T) {
			sink, valid := unclaimedServiceSink(t)
			invalid := valid
			row.bad(&invalid)
			service, err := NewService(invalid)
			require(t, service == nil && err != nil && err.Error() == row.want, "construction=(%p,%v), want %q", service, err, row.want)
			require(t, valid.SyncEngine.DATTLBindingService() == nil, "refused construction published a binding")
			first := newBoundService(t, valid)
			requireFirstClaimant(t, sink, valid, first)
		})
	}
}

// TestDATTLCallbackServiceConcurrentConstruction drives the production selection under -race: two constructions race
// three ACCEPTED/NEW SyncEngine.ApplyBlock publications; every selection registers with one whole OPEN constructed
// Service, so all three decreases are admitted, and the final binding is one of the racing constructions.
func TestDATTLCallbackServiceConcurrentConstruction(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xe3)
	built := make(chan *Service, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			service, err := NewService(h.service.cfg)
			if err != nil {
				t.Errorf("NewService: %v", err)
				return
			}
			built <- service
		}()
	}
	close(start)
	probe.apply()
	probe.apply()
	probe.f.requireRetained(probe.commit, "count 1 after two racing selections")
	probe.apply()
	waitWithin(t, &wg, "the racing goroutines")
	close(built)
	probe.f.requireAbsent(probe.commit, "every racing selection admitted its decrease")
	services := map[node.DATTLMutationService]bool{}
	for service := range built {
		services[service] = true
		t.Cleanup(func() { _ = service.Close() })
	}
	require(t, len(services) == 2 && services[h.syncEngine.DATTLBindingService()], "final binding outside the racing constructions")
}

// TestDATTLCallbackServiceCloseRace pins Close(S1) racing the registration of a selection that snapshotted S1 while S2
// binds. The outcome is admitted before DRAINING with Close waiting for the decrease, or refused with zero effects.
func TestDATTLCallbackServiceCloseRace(t *testing.T) {
	for i := range 20 {
		h := newTestHarness(t, 0, "127.0.0.1:0", nil)
		snapshot := h.syncEngine.DATTLBindingService()
		var closeReturned atomic.Bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = h.service.Close(); closeReturned.Store(true) }()
		var s2Err error
		go func() { defer wg.Done(); _, s2Err = NewService(h.service.cfg) }()
		decreases, closedDuring := 0, false
		err := snapshot.EnterDATTLMutation(func() error {
			decreases++
			closedDuring = closeReturned.Load()
			return nil
		})
		waitWithin(t, &wg, "the racing goroutines")
		require(t, s2Err == nil, "round %d: NewService(S2)=%v", i, s2Err)
		admitted := err == nil && decreases == 1 && !closedDuring
		refused := errors.Is(err, errServiceClosed) && reflect.TypeOf(err) == reflect.TypeOf(errServiceClosed) && decreases == 0
		require(t, snapshot == node.DATTLMutationService(h.service) && (admitted || refused), "round %d: err=%v decreases=%d closedDuring=%v", i, err, decreases, closedDuring)
		if current, ok := h.syncEngine.DATTLBindingService().(*Service); ok && current != h.service {
			_ = current.Close()
		}
	}
}

// TestDATTLCallbackEndToEndCloseRace drives the production selection: Close(S1) and the construction of S2 race one
// ACCEPTED/NEW SyncEngine.ApplyBlock publication whose selection snapshots S1 or S2. The apply returns ACCEPTED/NEW,
// Close returns, a probe of the commit reports DAAdmissionDuplicate or DAAdmissionRetained, and the binding names S2.
func TestDATTLCallbackEndToEndCloseRace(t *testing.T) {
	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	for i := range 5 {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		probe := newSelectionProbe(t, h, source, 0xe4)
		probe.apply()
		probe.apply()
		var wg sync.WaitGroup
		var s2 *Service
		var s2Err error
		wg.Add(2)
		go func() { defer wg.Done(); _ = h.service.Close() }()
		go func() {
			defer wg.Done()
			s2, s2Err = NewService(h.service.cfg)
		}()
		probe.apply()
		waitWithin(t, &wg, "the racing goroutines")
		got, err := probe.f.probe(probe.commit)
		require(t, err == nil && (got.Disposition == node.DAAdmissionDuplicate || got.Disposition == node.DAAdmissionRetained), "round %d: probe=(%+v,%v), want kept by a refusal or expired by one decrease", i, got, err)
		require(t, s2Err == nil && s2 != nil, "round %d: NewService(S2)=%v", i, s2Err)
		require(t, h.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "round %d: binding is not S2", i)
		requireReturned(t, lifecycleClose(s2), fmt.Sprintf("round %d: Close(S2)", i))
	}
}

// detachedReorgFixture is a sink tip block carrying one DA commit and chunk, plus a longer source branch that a peer or
// local apply reorganizes onto.
type detachedReorgFixture struct {
	commitRaw, chunkRaw []byte
	oldTip              [32]byte
	branch              [][]byte
}

// mineDetachedReorgFixture mines the common chain on source and applies it to sink, mines the sink DA block, and mines
// branchLen source blocks on the common chain without applying them. When spendChunkInput is set, the first branch
// block spends the chunk's input, so the requeue retains only the commit, a counted State B record.
func mineDetachedReorgFixture(t *testing.T, source, sink *testHarness, branchLen int, spendChunkInput bool) detachedReorgFixture {
	t.Helper()
	signer := mustP2PMLDSA87Keypair(t)
	mineAddress := consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())
	timestamp := uint64(1_778_000_000)
	minerConfig := func(provider node.CompleteDASetProvider, offset uint64) node.MinerConfig {
		cfg := node.DefaultMinerConfig()
		cfg.MineAddress = append([]byte(nil), mineAddress...)
		cfg.CompleteDASetProvider = provider
		cfg.TimestampSource = func() uint64 { timestamp += offset; return timestamp }
		return cfg
	}
	commonMiner, err := node.NewMiner(source.chainState, source.blockStore, source.syncEngine, minerConfig(nil, 1))
	must(t, err, "NewMiner(common)")
	spendable := make([]consensus.Outpoint, 0, 2)
	spendValues := make([]uint64, 0, 2)
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

// detachedReorgHookRetains reorganizes the sink DA block away with a two-block source branch; the engine's
// detached-reorg hook admits the commit only if its Service is OPEN. It reports whether the commit is retained.
func detachedReorgHookRetains(t *testing.T, source, sink *testHarness) bool {
	t.Helper()
	fixture := mineDetachedReorgFixture(t, source, sink, 2, false)
	for i, block := range fixture.branch {
		_, err := sink.syncEngine.ApplyBlockWithReorg(block, nil)
		must(t, err, fmt.Sprintf("apply branch %d", i))
	}
	require(t, sink.chainState.TipHash == source.chainState.TipHash && sink.chainState.TipHash != fixture.oldTip, "reorganization did not move the sink tip")
	result, err := sink.syncEngine.DARelayState().AdmitDA(fixture.commitRaw, node.DetachedReorgDAProvenance())
	must(t, err, "retained commit probe")
	return result.Disposition == node.DAAdmissionDuplicate
}

// requireCommitRetained reports through LookupRetainedTx, which changes nothing, whether the requeued commit is
// retained and fails unless it equals want.
func requireCommitRetained(t *testing.T, h *testHarness, fixture detachedReorgFixture, want bool, step string) {
	t.Helper()
	_, txid, _, _, err := consensus.ParseTx(fixture.commitRaw)
	must(t, err, "ParseTx(commit)")
	_, present, err := h.syncEngine.DARelayState().LookupRetainedTx(txid)
	require(t, err == nil && present == want, "%s: commit present=%v err=%v, want present=%v", step, present, err, want)
}

// TestDATTLCallbackEndToEndReorgRequeueNotDecreased pins that the requeue is not decreased, through a peer's lease
// path: a winning reorganization disconnects the sink block carrying one DA commit and chunk while its first block
// spends the chunk's input, so the requeue retains the commit alone at count 3. The publication that requeued it does
// not decrease it: it survives the next two counted publications and expires at the third.
func TestDATTLCallbackEndToEndReorgRequeueNotDecreased(t *testing.T) {
	source := newTestHarness(t, 1, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	fixture := mineDetachedReorgFixture(t, source, sink, 5, true)
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
	requireCommitRetained(t, sink, fixture, true, "requeued by the reorganization")
	_, chunkTxid, _, _, err := consensus.ParseTx(fixture.chunkRaw)
	must(t, err, "ParseTx(chunk)")
	_, chunkPresent, err := sink.syncEngine.DARelayState().LookupRetainedTx(chunkTxid)
	require(t, err == nil && !chunkPresent, "the chunk whose input the branch spent was retained: err=%v", err)
	for i := range 2 {
		relay(next + i)
	}
	requireCommitRetained(t, sink, fixture, true, "count 1 after two counted publications following the requeue")
	relay(next + 2)
	requireCommitRetained(t, sink, fixture, false, "expired at the third counted publication following the requeue")
}

// TestDATTLCallbackLaterConstructionKeepsFirstHook pins the later-construction claim end to end through a real
// reorganization: S2 over the same SyncEngine succeeds with the same relay and becomes the binding, while the
// detached-reorg hook stays with the first claimant S1. With S1 CLOSED and S2 OPEN the disconnected commit is refused
// (S1's closed path) and not retained; the control with S1 OPEN retains it.
func TestDATTLCallbackLaterConstructionKeepsFirstHook(t *testing.T) {
	for _, closeFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("first claimant closed=%v", closeFirst), func(t *testing.T) {
			source := newTestHarness(t, 1, "127.0.0.1:0", nil)
			sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
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

// daRelayPublicImage is the DA relay image observable through the exported surface: the A/B/C member identities in txid
// order (the exported order is unspecified), each member's retained bytes and the complete-set candidates.
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

// TestDATTLCallbackLaterConstructionChangesNoDAState pins that a later construction changes nothing: over a relay
// populated with a State A chunk and a State B commit, a later NewService S2 (and so its ClaimDARelayState and binding
// publication) leaves the exported relay image unchanged. Counts and owner tokens are not exported; the node test
// TestDATTLCallbackBindingChangesNoDAState compares them around the same claim and binding steps.
func TestDATTLCallbackLaterConstructionChangesNoDAState(t *testing.T) {
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

// TestDATTLCallbackEndToEndSelection drives the no-lease selection through real ACCEPTED/NEW applies
// (SyncEngine.ApplyBlock) over the real DA owner and Services: the bound OPEN Service admits one decrease per
// publication, AnnounceBlock decreases nothing, a CLOSED current binding changes no count while the apply still returns
// ACCEPTED/NEW, and a fresh Service binds and decreases while the closed Service's retained AnnounceBlock returns
// "service already closed" and decreases nothing.
func TestDATTLCallbackEndToEndSelection(t *testing.T) {
	source, h, probe := newSourceAndProbe(t, 7, 0xd1)
	require(t, probe.next == 1, "first applied height=%d, want 1", probe.next)
	probe.apply()
	probe.apply()
	probe.f.requireRetained(probe.commit, "count 1 after two selected decreases")
	must(t, h.service.AnnounceBlock(blockAtHeight(t, source, 2)), "AnnounceBlock(2)")
	must(t, h.service.AnnounceBlock(blockAtHeight(t, source, 3)), "AnnounceBlock(3)")
	probe.f.requireRetained(probe.commit, "AnnounceBlock decreased nothing")
	must(t, h.service.Close(), "Close(S1)")
	probe.apply()
	probe.f.requireRetained(probe.commit, "the CLOSED binding refused the decrease")
	s2 := newBoundService(t, h.service.cfg)
	require(t, h.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "S2 binding")
	fresh := probe.f.commit(daRelayTestID(0xd6), 2)
	probe.f.admit(fresh, "127.0.0.1:19112")
	probe.apply()
	probe.f.requireAbsent(probe.commit, "the record S2's admitted decrease expired at count 1")
	probe.apply()
	probe.f.requireRetained(fresh, "count 1 after two publications: S2 decreased once per publication")
	requireClosedRejection(t, h.service.AnnounceBlock(blockAtHeight(t, source, probe.next)), "the closed Service's retained AnnounceBlock")
	probe.f.requireRetained(fresh, "the closed AnnounceBlock decreased nothing")
	probe.apply()
	probe.f.requireAbsent(fresh, "the third decrease expired the record")
}

// TestDATTLCallbackEndToEndLeasePath pins the lease path end to end through the peer's applyBlockWithReorg: with State
// A X at 2, State B Y at 1 and a State C set Z retained, one relayed block leaves X at 1, removes Y and keeps Z; the
// binding names another OPEN Service S2 whose wrapper records zero entry attempts.
func TestDATTLCallbackEndToEndLeasePath(t *testing.T) {
	source, h, probe := newSourceAndProbe(t, 5, 0xd2)
	s2 := &wrappedTTLEntry{inner: newBoundService(t, h.service.cfg)}
	h.syncEngine.PublishDATTLBinding(s2)
	p := testPeerForService(h.service, "remote", 3)
	holdWorkLease(t, h.service)
	relayAccepted(t, p, source, 1)
	stateA := probe.f.chunk(daRelayTestID(0xa2), 0, []byte("lease-x"))
	probe.f.admit(stateA, "lease-a")
	zID := daRelayTestID(0xc2)
	zCommitment := sha3.Sum256([]byte("lease-z"))
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
	probe.f.requireRetained(probe.commit, "Y at count 1")
	requireClaimed(spendY, "a spend of Y's input while Y holds its claim")
	requireZ("before the apply")
	relayAccepted(t, p, source, 3)
	requireExpired(probe.commit, spendY, "Y")
	probe.f.requireRetained(stateA, "X at count 1")
	requireZ("after the apply")
	requireClaimed(spendX, "a spend of X's input while X holds its claim")
	relayAccepted(t, p, source, 4)
	requireExpired(stateA, spendX, "X")
	requireZ("after a State A record expires")
	require(t, s2.attempts.Load() == 0, "the OPEN bound S2 recorded %d entry attempts, want 0", s2.attempts.Load())
}

// TestDATTLCallbackEndToEndPanicReleasesLease pins the entry under a panic: a panic inside the decrease passed to the
// bound Service's registered entry propagates unrecovered, the lease is released once, and Close returns.
func TestDATTLCallbackEndToEndPanicReleasesLease(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	recovered := func() (value any) {
		defer func() { value = recover() }()
		_ = h.service.EnterDATTLMutation(func() error { panic("ttl body panic") })
		return nil
	}()
	require(t, recovered == "ttl body panic", "panic value=%v, want the original propagated unrecovered", recovered)
	requireReturned(t, lifecycleClose(h.service), "Close after the panicking entry")
}

// TestDATTLCallbackEndToEndErrorReleasesLease pins the entry on a decrease that returns an error: the decrease runs
// once under one registered lease, on which a Close started inside it waits; it returns that error unchanged and
// releases the lease, so Close returns.
func TestDATTLCallbackEndToEndErrorReleasesLease(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	refusal := errors.New("ttl body refusal")
	var closed chan error
	calls := 0
	got := h.service.EnterDATTLMutation(func() error {
		calls++
		closed = lifecycleClose(h.service)
		waitDraining(t, h.service)
		requireStillBlocked(t, closed, "Close while the registered decrease runs")
		return refusal
	})
	require(t, errors.Is(got, refusal) && reflect.TypeOf(got) == reflect.TypeOf(refusal) && calls == 1, "entry=%v after %d decrease calls, want the decrease's own error value after 1", got, calls)
	requireReturned(t, closed, "Close after the entry released its lease")
}

// TestDATTLCallbackEndToEndPanicWhileCloseWaits pins the panic while Close waits (RUBIN_L1_P2P_AUX.md Section 5): Close
// starts while the registered entry runs, reaches DRAINING and waits on the entry's lease; the decrease then panics,
// the panic propagates unrecovered, the lease is released once, and the waiting Close returns.
func TestDATTLCallbackEndToEndPanicWhileCloseWaits(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	entered, unwind := make(chan struct{}), make(chan struct{})
	var unwindOnce sync.Once
	release := func() { unwindOnce.Do(func() { close(unwind) }) }
	t.Cleanup(release)
	var got any
	exited := make(chan error, 1)
	go func() {
		defer func() { got = recover(); exited <- nil }()
		_ = h.service.EnterDATTLMutation(func() error { close(entered); <-unwind; panic("ttl body panic") })
	}()
	select {
	case <-entered:
	case <-exited:
		t.Fatalf("EnterDATTLMutation returned (%v) without invoking the decrease", got)
	case <-time.After(lifecycleWatchdog):
		t.Fatalf("the decrease was not invoked within %s", lifecycleWatchdog)
	}
	closed := lifecycleClose(h.service)
	waitDraining(t, h.service)
	requireStillBlocked(t, closed, "Close")
	release()
	requireReturned(t, exited, "the panicking entry after the release")
	require(t, got == "ttl body panic", "panic value, want the original propagated unrecovered")
	requireReturned(t, closed, "the waiting Close after the panicking entry")
}

// mineSideBlock mines a height-1 block on a fresh chain paying a fresh key, so its hash differs from the shared test
// chain's blocks: relayed to a node whose tip is at height 2, it is a valid side-branch block with less work.
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

// relayAccepted relays source's block at height through p and requires an applied summary.
func relayAccepted(t *testing.T, p *peer, source *testHarness, height uint64) {
	t.Helper()
	summary, err := p.processRelayedBlock(blockAtHeight(t, source, height))
	require(t, err == nil && summary != nil, "processRelayedBlock(%d)=(%+v,%v)", height, summary, err)
}

// TestDATTLCallbackEndToEndNonAcceptedResults pins the non-accepted results end to end over the real SyncEngine, DA
// owner and Service, counting through the retained image: a valid side-branch block stored non-canonical, a
// KNOWN_BLOCK_NOOP replay, a MISSING_PARENT block retained as an orphan, a CONSENSUS_INVALID block and a DisconnectTip
// decrease nothing, so the record retained at count 3 survives the next two counted publications and expires only at
// the third. Peer calls hold a work lease; the direct side block and DisconnectTip make zero attempts on the entry.
func TestDATTLCallbackEndToEndNonAcceptedResults(t *testing.T) {
	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	sideBlock := mineSideBlock(t)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := testPeerForService(h.service, "remote", 5)
	holdWorkLease(t, h.service)
	relayAccepted(t, p, source, 1)
	relayAccepted(t, p, source, 2)
	probe := newSelectionProbe(t, h, source, 0xd3)
	entry := &wrappedTTLEntry{inner: h.service}
	h.syncEngine.PublishDATTLBinding(entry)
	sideHash, err := consensus.BlockHash(sideBlock[:consensus.BLOCK_HEADER_BYTES])
	must(t, err, "BlockHash(side block)")
	known, err := h.service.hasBlock(sideHash)
	require(t, err == nil && !known, "the side block is already known: err=%v", err)
	summary, err := h.syncEngine.ApplyBlockWithReorg(sideBlock, nil)
	require(t, err == nil && summary != nil && len(summary.CanonicalAppliedBlocks) == 0 && h.chainState.Height == 2, "side block=(%+v,%v) height=%d, want stored non-canonical", summary, err, h.chainState.Height)
	summary, err = p.processRelayedBlock(blockAtHeight(t, source, 2))
	require(t, err == nil && summary == nil, "known block replay=(%+v,%v), want KNOWN_BLOCK_NOOP", summary, err)
	summary, err = p.processRelayedBlock(blockAtHeight(t, source, 5))
	require(t, err == nil && summary == nil && h.service.orphans.Len() == 1, "missing parent=(%+v,%v) orphans=%d, want one retained orphan", summary, err, h.service.orphans.Len())
	invalid := append([]byte(nil), blockAtHeight(t, source, 3)...)
	invalid[4+32] ^= 0xff // the merkle root
	summary, err = testPeerForService(h.service, "invalid", 5).processRelayedBlock(invalid)
	var invalidErr *consensus.TxError
	require(t, errors.As(err, &invalidErr) && invalidErr.Code == consensus.BLOCK_ERR_MERKLE_INVALID && summary == nil && h.chainState.Height == 2, "invalid block=(%+v,%v), want BLOCK_ERR_MERKLE_INVALID", summary, err)
	relayAccepted(t, p, source, 3)
	disconnected, err := h.syncEngine.DisconnectTip()
	require(t, err == nil && disconnected != nil && h.chainState.Height == 2, "DisconnectTip=(%+v,%v)", disconnected, err)
	require(t, entry.attempts.Load() == 0, "entry attempts=%d before the reconnect, want 0", entry.attempts.Load())
	reconnected, err := h.syncEngine.ApplyBlock(blockAtHeight(t, source, 3), nil)
	require(t, err == nil && reconnected != nil, "reconnect(3)=(%+v,%v)", reconnected, err)
	probe.f.requireRetained(probe.commit, "count 1: two counted publications after the side block, replay and disconnect")
	relayAccepted(t, p, source, 4)
	probe.f.requireAbsent(probe.commit, "the record the third counted publication expired")
}

// TestDATTLCallbackEndToEndStoredSideBlockThroughPeer pins the stored non-canonical result on the peer's lease path: a
// valid side-branch block relayed by a peer is stored non-canonical and decreases nothing, so the commit retained at
// count 3 survives the next two counted publications and expires only at the third.
func TestDATTLCallbackEndToEndStoredSideBlockThroughPeer(t *testing.T) {
	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	sideBlock := mineSideBlock(t)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := testPeerForService(h.service, "remote", 5)
	holdWorkLease(t, h.service)
	relayAccepted(t, p, source, 1)
	relayAccepted(t, p, source, 2)
	probe := newSelectionProbe(t, h, source, 0xd4)
	sideHash, err := consensus.BlockHash(sideBlock[:consensus.BLOCK_HEADER_BYTES])
	must(t, err, "BlockHash(side block)")
	known, err := h.service.hasBlock(sideHash)
	require(t, err == nil && !known, "the side block is already known: err=%v", err)
	_, err = p.processRelayedBlock(sideBlock)
	must(t, err, "processRelayedBlock(side block)")
	stored, err := h.blockStore.GetBlockByHash(sideHash)
	require(t, err == nil && bytes.Equal(stored, sideBlock) && h.chainState.Height == 2 && h.chainState.TipHash != sideHash, "side block stored=%v err=%v height=%d, want stored non-canonical", stored != nil, err, h.chainState.Height)
	relayAccepted(t, p, source, 3)
	relayAccepted(t, p, source, 4)
	probe.f.requireRetained(probe.commit, "count 1: two counted publications after the stored side block")
	relayAccepted(t, p, source, 5)
	probe.f.requireAbsent(probe.commit, "the record the third counted publication expired")
}

// TestDATTLCallbackEndToEndDrainingBindingRefused drives the production no-lease selection through
// SyncEngine.ApplyBlock while the current binding's Service S2 is DRAINING and the earlier S1 is OPEN: the publication
// still returns ACCEPTED/NEW, the registration is refused with zero DA effects and nothing falls back to S1, Close(S2)
// returns only after the held lease is released, and a fresh Service then binds and decreases.
func TestDATTLCallbackEndToEndDrainingBindingRefused(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xd5)
	probe.apply()
	probe.apply()
	s2 := newBoundService(t, h.service.cfg)
	release := holdWorkLease(t, s2)
	closeDone := lifecycleClose(s2)
	waitDraining(t, s2)
	probe.apply()
	probe.f.requireRetained(probe.commit, "the DRAINING binding refused the decrease and nothing fell back to the OPEN S1")
	requireStillBlocked(t, closeDone, "Close(S2)")
	release()
	requireReturned(t, closeDone, "Close(S2) after the release")
	require(t, h.service.workAuthorized() && h.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "S1 left OPEN and the binding kept naming S2")
	newBoundService(t, h.service.cfg)
	probe.apply()
	probe.f.requireAbsent(probe.commit, "the fresh binding's admitted decrease expired the record at count 1")
}

// wrappedTTLEntry is a binding over a real Service's own entry that runs before ahead of each attempt, counts attempts
// and returns refuse, when set, instead of entering.
type wrappedTTLEntry struct {
	inner    *Service
	before   func()
	refuse   error
	attempts atomic.Int64
}

func (w *wrappedTTLEntry) EnterDATTLMutation(decrease func() error) error {
	w.attempts.Add(1)
	if w.before != nil {
		w.before()
	}
	if w.refuse != nil {
		return w.refuse
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

// TestDATTLCallbackEndToEndEntryInsideTheHold drives SyncEngine.ApplyBlock through the production selection and, inside
// the selected entry, starts a ReleasePeerQuotaKey and a DA admission: both park on the admission guard before the
// entry proceeds and both complete, so the entry runs inside the exclusive hold (RUBIN_COMPACT_BLOCKS.md Section 5);
// the admitted record is created after the decrease, so it is still retained after two more.
func TestDATTLCallbackEndToEndEntryInsideTheHold(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xe5)
	fresh := probe.f.chunk(daRelayTestID(0xe7), 0, []byte("in-hold"))
	done := make(chan error, 2)
	entry := &wrappedTTLEntry{inner: h.service}
	entry.before = func() {
		entry.before = nil
		go func() { done <- h.syncEngine.DARelayState().ReleasePeerQuotaKey("unrelated-peer") }()
		waitUntil(t, func() bool { return goroutineParked("RLockUnlessTerminal", "sync.(*Cond).Wait", "ReleasePeerQuotaKey") }, "ReleasePeerQuotaKey parked on the admission guard")
		go func() { done <- probe.f.tryAdmit(fresh, "in-hold-peer") }()
		waitUntil(t, func() bool { return goroutineParked("RLockUnlessTerminal", "sync.(*Cond).Wait", "AdmitDA") }, "AdmitDA parked on the admission guard")
	}
	h.syncEngine.PublishDATTLBinding(entry)
	probe.apply()
	for range 2 {
		select {
		case err := <-done:
			must(t, err, "parked writer after the guard release")
		case <-time.After(lifecycleWatchdog):
			t.Fatalf("a parked writer never proceeded after the guard release")
		}
	}
	require(t, entry.attempts.Load() == 1, "entry attempts=%d, want 1", entry.attempts.Load())
	probe.apply()
	probe.f.requireRetained(probe.commit, "count 1 after two in-hold decreases")
	probe.apply()
	probe.f.requireAbsent(probe.commit, "the third decrease expired the original record")
	probe.f.requireRetained(fresh, "the record admitted after the first decrease at count 1")
}

// TestDATTLCallbackEndToEndEntryErrorConsumed pins that the transition consumes the entry result: an entry returning an
// error leaves ApplyBlock's ACCEPTED/NEW summary and nil error, decreases nothing, and later ones decrease.
func TestDATTLCallbackEndToEndEntryErrorConsumed(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xe6)
	failing := &wrappedTTLEntry{inner: h.service, refuse: errors.New("ttl entry failure")}
	h.syncEngine.PublishDATTLBinding(failing)
	probe.apply()
	require(t, failing.attempts.Load() == 1, "entry attempts=%d, want 1", failing.attempts.Load())
	h.syncEngine.PublishDATTLBinding(h.service)
	probe.apply()
	probe.apply()
	probe.f.requireRetained(probe.commit, "count 1: the failed entry decreased nothing")
	probe.apply()
	probe.f.requireAbsent(probe.commit, "the third admitted decrease expired the record")
}

// TestDATTLCallbackEndToEndPreCommitLatchInvokesNothing pins that a transition latching before the durable commit
// invokes no entry: the bound entry records zero attempts across the latching SyncEngine.ApplyBlock.
func TestDATTLCallbackEndToEndPreCommitLatchInvokesNothing(t *testing.T) {
	source := newTestHarness(t, 4, "127.0.0.1:0", nil)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	entry := &wrappedTTLEntry{inner: h.service}
	h.syncEngine.PublishDATTLBinding(entry)
	latchDAHarness(t, h, source)
	require(t, entry.attempts.Load() == 0, "pre-commit latch entry attempts=%d, want 0", entry.attempts.Load())
}

// TestDATTLCallbackEndToEndDrainingLease pins the lease path while the lease-owning Service is DRAINING: with the
// worker lease held and Close waiting on it, the peer's applies still run the nested entry, which registers nothing, so
// three ACCEPTED/NEW publications expire the record; Close returns only after the lease is released.
func TestDATTLCallbackEndToEndDrainingLease(t *testing.T) {
	source, h, probe := newSourceAndProbe(t, 6, 0xe7)
	p := testPeerForService(h.service, "remote", 5)
	release := holdWorkLease(t, h.service)
	closeDone := lifecycleClose(h.service)
	waitDraining(t, h.service)
	for height := uint64(1); height <= 3; height++ {
		relayAccepted(t, p, source, height)
		if height == 2 {
			probe.f.requireRetained(probe.commit, "count 1 after two nested decreases while DRAINING")
		}
	}
	requireStillBlocked(t, closeDone, "Close")
	release()
	requireReturned(t, closeDone, "Close after the release")
	probe.f.requireAbsent(probe.commit, "the third nested decrease expired the record")
}

// TestDATTLCallbackEndToEndAbsentBinding drives SyncEngine.ApplyBlock on an engine with no constructed Service: the
// binding is absent, so three ACCEPTED/NEW publications invoke nothing and the commit retained at count 3 survives
// them. A Service constructed afterwards binds, and its three admitted decreases then expire the same record.
func TestDATTLCallbackEndToEndAbsentBinding(t *testing.T) {
	source := newTestHarness(t, 7, "127.0.0.1:0", nil)
	sink, cfg := unclaimedServiceSink(t)
	require(t, sink.syncEngine.DATTLBindingService() == nil, "binding present with no constructed Service")
	sink.service = &Service{daRelay: sink.syncEngine.DARelayState()}
	f := newDAIngressFixture(t, sink)
	commit := f.commit(daRelayTestID(0xe8), 2)
	f.admit(commit, "127.0.0.1:19111")
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
	f.requireRetained(commit, "three publications under an absent binding decreased nothing")
	newBoundService(t, cfg)
	for height := start + 3; height < start+6; height++ {
		if apply(height); height == start+4 {
			f.requireRetained(commit, "count 1 after two admitted decreases: the absent binding kept count 3")
		}
	}
	f.requireAbsent(commit, "the bound Service's third admitted decrease expired the record")
}

// requireAbsentBindingDecreasesNothing retains a commit at count 3 in sink's DA relay and applies three ACCEPTED/NEW
// SyncEngine.ApplyBlock publications: with no binding the record survives. DisconnectTip then restores the tip.
func requireAbsentBindingDecreasesNothing(t *testing.T, sink *testHarness) {
	t.Helper()
	source := newTestHarness(t, int(sink.chainState.Height)+4, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, sink)
	commit := f.commit(daRelayTestID(0xe9), 2)
	f.admit(commit, "127.0.0.1:19111")
	start := sink.chainState.Height + 1
	for height := start; height < start+3; height++ {
		summary, err := sink.syncEngine.ApplyBlock(blockAtHeight(t, source, height), nil)
		require(t, err == nil && summary != nil && summary.BlockHeight == height, "ApplyBlock(%d)=(%+v,%v), want ACCEPTED/NEW", height, summary, err)
	}
	require(t, sink.syncEngine.DATTLBindingService() == nil, "an apply published a binding")
	f.requireRetained(commit, "three publications under an absent binding decreased nothing")
	for range 3 {
		_, err := sink.syncEngine.DisconnectTip()
		must(t, err, "DisconnectTip back to the starting tip")
	}
	require(t, sink.chainState.Height+1 == start, "tip height=%d after the disconnects, want %d", sink.chainState.Height, start-1)
}

// TestDATTLCallbackEndToEndSnapshotBeforePublication drives SyncEngine.ApplyBlock through the production selection
// while a publication of S2 lands after the selection snapshotted S1 and before its registration: the registration goes
// to S1 exactly once, S2 records no attempt, the decrease is admitted; the next two select S2 and expire it.
func TestDATTLCallbackEndToEndSnapshotBeforePublication(t *testing.T) {
	_, h, probe := newSourceAndProbe(t, 6, 0xea)
	s2 := &wrappedTTLEntry{inner: newBoundService(t, h.service.cfg)}
	var once sync.Once
	s1 := &wrappedTTLEntry{inner: h.service}
	s1.before = func() { once.Do(func() { h.syncEngine.PublishDATTLBinding(s2) }) }
	h.syncEngine.PublishDATTLBinding(s1)
	probe.apply()
	require(t, s1.attempts.Load() == 1 && s2.attempts.Load() == 0, "first publication attempts S1=%d S2=%d, want 1 and 0: a second selection or fan-out after the registration reached S2", s1.attempts.Load(), s2.attempts.Load())
	require(t, h.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "binding after the publication, want S2")
	probe.apply()
	probe.f.requireRetained(probe.commit, "count 1: S1's snapshotted registration and S2's decreased once each")
	probe.apply()
	require(t, s1.attempts.Load() == 1 && s2.attempts.Load() == 2, "attempts S1=%d S2=%d, want 1 and 2", s1.attempts.Load(), s2.attempts.Load())
	probe.f.requireAbsent(probe.commit, "the third admitted decrease expired the record")
}

// TestDATTLCallbackEndToEndNoGuardReacquisition drives three ACCEPTED/NEW publications through the production
// selection, each ApplyBlock bounded by the watchdog: the entry is attempted once for the first, and the record's count
// shows each body ran (retained at count 1 after the second, expired by the third).
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
	probe.f.requireRetained(probe.commit, "count 1: the first publication's body decreased it")
	apply(probe.next+2, blocks[2])
	probe.f.requireAbsent(probe.commit, "the third counted publication expired the record")
}

// closeRaceEntry is a binding over S1's own entry that, on its one attempt, starts the race and records whether S1
// admitted the decrease and Close(S1) had returned.
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

// TestDATTLCallbackEndToEndCloseRaceOutcomes drives SyncEngine.ApplyBlock through the production selection with S1
// snapshotted, and starts Close(S1) and the construction of S2 between the snapshot and S1's registration: the one
// registration goes to S1; either S1 admitted it before Close returned and the record at count 2 is at 1, or S1 refused
// it and the record is unchanged; nothing reaches S2, which is the binding afterwards and whose next decreases expire
// the record exactly when the S1 outcome predicts. Even rounds let Close(S1) and S2's binding finish before the
// registration, so S1 refuses; round 1 starts both inside S1's held decrease, so S1 admits and Close waits.
func TestDATTLCallbackEndToEndCloseRaceOutcomes(t *testing.T) {
	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	for i := range 8 {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		probe := newSelectionProbe(t, h, source, 0xec)
		probe.apply()
		var closeReturned atomic.Bool
		var s2 atomic.Pointer[Service]
		var wg sync.WaitGroup
		entry := &closeRaceEntry{inner: h.service, closeReturned: &closeReturned}
		entry.start = func(inside bool) {
			if inside != (i == 1) {
				return
			}
			wg.Add(2)
			go func() { defer wg.Done(); _ = h.service.Close(); closeReturned.Store(true) }()
			go func() {
				defer wg.Done()
				if service, err := NewService(h.service.cfg); err == nil {
					s2.Store(service)
				}
			}()
			if inside {
				waitUntil(t, func() bool { return s2.Load() != nil }, "S2 bound while the decrease is held")
				waitDraining(t, h.service)
				waitUntil(t, func() bool {
					return closeReturned.Load() || goroutineParked("[sync.WaitGroup.Wait", "(*Service).Close", "TestDATTLCallbackEndToEndCloseRaceOutcomes")
				}, "Close(S1) parked on its work leases or returned")
				require(t, !closeReturned.Load(), "Close(S1) returned while its registered decrease ran")
			} else if i%2 == 0 {
				waitWithin(t, &wg, "the racing goroutines")
			}
		}
		h.syncEngine.PublishDATTLBinding(entry)
		probe.apply()
		waitWithin(t, &wg, "the racing goroutines")
		require(t, entry.attempts == 1 && !entry.afterExit, "round %d: attempts=%d decrease after Close returned=%v", i, entry.attempts, entry.afterExit)
		require(t, i%2 != 0 || !entry.ran, "round %d: S1 admitted a registration after Close returned", i)
		probe.f.requireRetained(probe.commit, fmt.Sprintf("round %d: one decrease at most from count 2", i))
		service := s2.Load()
		require(t, service != nil && h.syncEngine.DATTLBindingService() == node.DATTLMutationService(service), "round %d: S2 construction and binding", i)
		if !entry.ran {
			probe.apply()
			probe.f.requireRetained(probe.commit, fmt.Sprintf("round %d: S1 refused with zero effects", i))
		}
		probe.apply()
		probe.f.requireAbsent(probe.commit, fmt.Sprintf("round %d: S2's decrease expired the record", i))
		requireReturned(t, lifecycleClose(service), fmt.Sprintf("round %d: Close(S2)", i))
	}
}
