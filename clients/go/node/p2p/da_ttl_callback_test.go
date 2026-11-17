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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// selectDATTL is a test-local mirror of node's unexported enterSelectedDATTL over the public
// binding surface (one identity snapshot, then one registration attempt with that Service's own
// entry) that also returns the snapshotted Service. The production selection itself is observed
// by the node rows in clients/go/node/da_ttl_callback_test.go.
// errDATTLBindingAbsent is selectDATTL's report that no binding is published, so no entry ran.
var errDATTLBindingAbsent = errors.New("no DA TTL binding is published")

func selectDATTL(engine *node.SyncEngine, decrease func() error) (node.DATTLMutationService, error) {
	service := engine.DATTLBindingService()
	if service == nil {
		return nil, errDATTLBindingAbsent
	}
	return service, service.EnterDATTLMutation(decrease)
}

func newBoundService(t *testing.T, cfg ServiceConfig) *Service {
	t.Helper()
	service, err := NewService(cfg)
	require(t, err == nil && service != nil, "NewService: %v", err)
	t.Cleanup(func() { _ = service.Close() })
	return service
}

// TestDATTLCallbackServiceBinding pins the API-level Service rows over real Services sharing one
// SyncEngine: the latest successful construction is the binding whatever the lifecycle of earlier
// ones (C5), an admitted registration runs the decrease once under that Service's lease, a
// snapshot taken before a later construction registers with the snapshotted Service (C5 A10), a
// DRAINING or CLOSED binding refuses with zero effects and no fallback (R3), and the identity
// read follows constructions (C13).
func TestDATTLCallbackServiceBinding(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	engine, s1 := h.syncEngine, h.service
	require(t, engine.DATTLBindingService() == node.DATTLMutationService(s1), "identity read after S1 construction")
	s2 := newBoundService(t, h.service.cfg)
	require(t, s2.daRelay == s1.daRelay && engine.DATTLBindingService() == node.DATTLMutationService(s2), "identity read after S2 construction")
	decreases := 0
	selected, err := selectDATTL(engine, func() error { decreases++; return nil })
	require(t, err == nil && selected == node.DATTLMutationService(s2) && decreases == 1, "both OPEN: selected=%p err=%v decreases=%d", selected, err, decreases)

	snapshot := engine.DATTLBindingService()
	s3 := newBoundService(t, h.service.cfg)
	require(t, engine.DATTLBindingService() == node.DATTLMutationService(s3), "S3 binding")
	err = snapshot.EnterDATTLMutation(func() error {
		decreases++
		require(t, !s2.closeReturnsWithin(50*time.Millisecond), "snapshotted S2 lease not held during the decrease")
		return nil
	})
	require(t, err == nil && decreases == 2, "snapshot registration err=%v decreases=%d", err, decreases)

	require(t, s3.Close() == nil, "Close(S3)")
	selected, err = selectDATTL(engine, func() error { decreases++; return nil })
	require(t, selected == node.DATTLMutationService(s3) && errors.Is(err, errServiceClosed) && err.Error() == "service already closed" && decreases == 2, "CLOSED binding: selected=%p err=%v decreases=%d", selected, err, decreases)
	require(t, engine.DATTLBindingService() == node.DATTLMutationService(s3), "Close cleared or replaced the binding")

	s4 := newBoundService(t, h.service.cfg)
	require(t, s1.Close() == nil, "Close(S1)")
	selected, err = selectDATTL(engine, func() error { decreases++; return nil })
	require(t, err == nil && selected == node.DATTLMutationService(s4) && decreases == 3, "S1 CLOSED, S4 OPEN: selected=%p err=%v decreases=%d", selected, err, decreases)
}

// closeReturnsWithin starts Close and reports whether it returned within d; a Close still
// waiting is left to finish when the held lease is released.
func (s *Service) closeReturnsWithin(d time.Duration) bool {
	done := make(chan struct{})
	go func() { _ = s.Close(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// TestDATTLCallbackServiceDrainingRefused pins R3 for DRAINING: with S1 OPEN and S2 bound, S2's
// Close waits on a held lease; a registration while S2 is DRAINING is refused with the closed
// error and zero decreases, with no fallback to S1, and Close returns only after the release.
func TestDATTLCallbackServiceDrainingRefused(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	s2 := newBoundService(t, h.service.cfg)
	require(t, s2.acquireWork(), "lease on S2")
	closeDone := make(chan struct{})
	go func() { _ = s2.Close(); close(closeDone) }()
	deadline := time.Now().Add(lifecycleWatchdog)
	for s2.workAuthorized() {
		require(t, time.Now().Before(deadline), "S2 did not become DRAINING within %s", lifecycleWatchdog)
		runtime.Gosched()
	}
	decreases := 0
	selected, err := selectDATTL(h.syncEngine, func() error { decreases++; return nil })
	require(t, selected == node.DATTLMutationService(s2) && errors.Is(err, errServiceClosed) && err.Error() == "service already closed" && decreases == 0, "DRAINING binding: selected=%p err=%v decreases=%d", selected, err, decreases)
	select {
	case <-closeDone:
		t.Fatal("Close returned while the lease was held")
	default:
	}
	s2.releaseWork()
	select {
	case <-closeDone:
	case <-time.After(lifecycleWatchdog):
		t.Fatalf("Close did not return within %s after the release", lifecycleWatchdog)
	}
	require(t, h.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2) && h.service.workAuthorized(), "binding moved or S1 left OPEN")
}

// TestDATTLCallbackServiceConstructionFailure pins C7: a construction failing at config
// validation or at the inbound budget leaves the binding naming S1. On an engine with no claim
// yet, every such refusal claims nothing, so the next successful construction is the first
// claimant (F1): its admitDetachedReorgDA is the engine's detached-reorg hook.
func TestDATTLCallbackServiceConstructionFailure(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
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
	decreases := 0
	selected, err := selectDATTL(h.syncEngine, func() error { decreases++; return nil })
	require(t, err == nil && selected == node.DATTLMutationService(h.service) && decreases == 1, "selection after failures: selected=%p err=%v", selected, err)

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

// TestDATTLCallbackServiceConcurrentConstruction is the H1 API form under -race: concurrent
// constructions race selections; each selection registers with one whole constructed Service and
// the final binding is one of the racing constructions.
func TestDATTLCallbackServiceConcurrentConstruction(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
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
	var decreases atomic.Int64
	for range 50 {
		selected, err := selectDATTL(h.syncEngine, func() error { decreases.Add(1); return nil })
		_, isService := selected.(*Service)
		require(t, err == nil && isService, "selection selected=%T err=%v", selected, err)
	}
	wg.Wait()
	close(built)
	services := map[node.DATTLMutationService]bool{}
	for service := range built {
		services[service] = true
		t.Cleanup(func() { _ = service.Close() })
	}
	require(t, len(services) == 2 && services[h.syncEngine.DATTLBindingService()] && decreases.Load() == 50, "final binding outside the racing constructions: decreases=%d", decreases.Load())
}

// TestDATTLCallbackServiceCloseRace is the H2 API form: Close(S1) races the registration of a
// selection that snapshotted S1 while S2 binds. The outcome is either admitted before DRAINING
// with Close waiting for the decrease, or refused with zero effects; never S2.
func TestDATTLCallbackServiceCloseRace(t *testing.T) {
	for i := range 20 {
		h := newTestHarness(t, 0, "127.0.0.1:0", nil)
		snapshot := h.syncEngine.DATTLBindingService()
		var closeReturned atomic.Bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = h.service.Close(); closeReturned.Store(true) }()
		go func() { defer wg.Done(); _, _ = NewService(h.service.cfg) }()
		decreases, closedDuring := 0, false
		err := snapshot.EnterDATTLMutation(func() error {
			decreases++
			closedDuring = closeReturned.Load()
			return nil
		})
		wg.Wait()
		admitted := err == nil && decreases == 1 && !closedDuring
		refused := errors.Is(err, errServiceClosed) && decreases == 0
		require(t, snapshot == node.DATTLMutationService(h.service) && (admitted || refused), "round %d: err=%v decreases=%d closedDuring=%v", i, err, decreases, closedDuring)
		if current, ok := h.syncEngine.DATTLBindingService().(*Service); ok && current != h.service {
			_ = current.Close()
		}
	}
}

// detachedReorgFixture is a sink tip block carrying one DA commit and chunk, plus a longer
// source branch from their common parent that a peer or local apply reorganizes onto.
type detachedReorgFixture struct {
	commitRaw, chunkRaw []byte
	oldTip              [32]byte
	branch              [][]byte
}

// mineDetachedReorgFixture mines the common chain on source and applies it to sink, mines the
// sink DA block, and mines branchLen source blocks on the common chain without applying them.
// When spendChunkInput is set, the first branch block spends the chunk's input, so the requeue
// refuses the chunk and retains only the commit, which is then a counted State B record.
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

// detachedReorgHookRetains reorganizes the sink DA block away with a two-block source branch;
// the engine's detached-reorg hook admits the commit only if its Service is OPEN. It reports
// whether the disconnected commit is retained afterwards.
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

// requireCommitRetained reports through LookupRetainedTx, which changes nothing, whether the
// requeued commit is retained, and fails unless that equals want.
func requireCommitRetained(t *testing.T, h *testHarness, fixture detachedReorgFixture, want bool, step string) {
	t.Helper()
	_, txid, _, _, err := consensus.ParseTx(fixture.commitRaw)
	must(t, err, "ParseTx(commit)")
	_, present, err := h.syncEngine.DARelayState().LookupRetainedTx(txid)
	require(t, err == nil && present == want, "%s: commit present=%v err=%v, want present=%v", step, present, err, want)
}

// TestDATTLCallbackEndToEndReorgRequeueNotDecreased pins the requeue row through a peer's
// lease path: a winning reorganization disconnects the sink block carrying one DA commit and
// chunk while its first block spends the chunk's input, so the requeue retains the commit alone
// at count 3. The publication that requeued it does not decrease it: it survives the next two
// counted publications and expires at the third.
func TestDATTLCallbackEndToEndReorgRequeueNotDecreased(t *testing.T) {
	source := newTestHarness(t, 1, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	fixture := mineDetachedReorgFixture(t, source, sink, 5, true)
	p := testPeerForService(sink.service, "remote", 3)
	relay := func(i int) {
		t.Helper()
		_, err := p.processRelayedBlock(fixture.branch[i])
		must(t, err, fmt.Sprintf("processRelayedBlock(branch %d)", i))
	}
	// Fork choice may prefer the equal-work first branch block by its lower hash, so the
	// reorganization happens at the first relay that moves the tip off the sink DA block.
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
	relay(next)
	relay(next + 1)
	requireCommitRetained(t, sink, fixture, true, "count 1 after two counted publications following the requeue")
	relay(next + 2)
	requireCommitRetained(t, sink, fixture, false, "expired at the third counted publication following the requeue")
}

// TestDATTLCallbackLaterConstructionKeepsFirstHook pins C8 and F1 end to end through a real
// reorganization: S2 over the same SyncEngine succeeds with the same relay and becomes the
// binding, while the detached-reorg hook stays with the first claimant S1. With S1 CLOSED and
// S2 OPEN the disconnected commit is refused (S1's closed path) and not retained; the control
// with S1 OPEN retains it.
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

// daRelayPublicImage is the DA relay image observable through the exported surface: the A/B/C
// member identities in txid order (the exported order is unspecified), each member's retained
// bytes and the complete-set candidates.
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

// TestDATTLCallbackLaterConstructionChangesNoDAState is the C8 NOCHG row at the Service level:
// over a relay populated with a State A chunk and a State B commit, a later NewService S2 (and so
// its ClaimDARelayState and binding publication) leaves the exported relay image unchanged. Counts
// and owner tokens are not exported; the node row TestDATTLCallbackBindingChangesNoDAState
// compares them around the same claim and binding steps.
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

// TestDATTLCallbackEndToEndSelection drives the no-lease selection through real ACCEPTED/NEW
// applies (SyncEngine.ApplyBlock, the RPC miner's apply) over the real DA owner and Services: the
// bound OPEN Service admits one decrease per publication (C3, C10), AnnounceBlock decreases
// nothing (C3, C12), a CLOSED current binding refuses with zero DA effects and no fallback while
// the apply still returns ACCEPTED/NEW (R3, RES), the closed Service's retained
// AnnounceBlock returns "service already closed" (C12), and a fresh Service binds and decreases.
func TestDATTLCallbackEndToEndSelection(t *testing.T) {
	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	commit := f.commit(daRelayTestID(0xd1), 2)
	must(t, daRelayTestPeer(h, "127.0.0.1:19111", "127.0.0.1:19111").handleTx(commit), "retain the commit at count 3")
	apply := func(height uint64) {
		t.Helper()
		summary, err := h.syncEngine.ApplyBlock(blockAtHeight(t, source, height), nil)
		require(t, err == nil && summary != nil && summary.BlockHeight == height, "ApplyBlock(%d)=(%+v,%v), want ACCEPTED/NEW", height, summary, err)
	}
	apply(1)
	apply(2)
	f.requireRetained(commit, "count 1 after two selected decreases")
	must(t, h.service.AnnounceBlock(blockAtHeight(t, source, 2)), "AnnounceBlock(2)")
	must(t, h.service.AnnounceBlock(blockAtHeight(t, source, 3)), "AnnounceBlock(3)")
	f.requireRetained(commit, "AnnounceBlock decreased nothing")
	must(t, h.service.Close(), "Close(S1)")
	apply(3)
	f.requireRetained(commit, "the CLOSED binding refused the decrease")
	requireClosedRejection(t, h.service.AnnounceBlock(blockAtHeight(t, source, 4)), "the closed Service's retained AnnounceBlock")
	s2 := newBoundService(t, h.service.cfg)
	require(t, h.syncEngine.DATTLBindingService() == node.DATTLMutationService(s2), "S2 binding")
	apply(4)
	f.requireAbsent(commit, "the record S2's admitted decrease expired at count 1")
}

// TestDATTLCallbackEndToEndLeasePath pins the C1 lease-path row end to end: the peer path runs
// the lease-owning Service's own nested entry and never reads the binding, so with the binding
// naming a later, CLOSED Service S2 (whose selection would refuse) the peer applies still count
// 3 -> 2 -> 1 -> removed.
func TestDATTLCallbackEndToEndLeasePath(t *testing.T) {
	source := newTestHarness(t, 4, "127.0.0.1:0", nil)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	commit := f.commit(daRelayTestID(0xd2), 2)
	must(t, daRelayTestPeer(h, "127.0.0.1:19111", "127.0.0.1:19111").handleTx(commit), "retain the commit at count 3")
	s2 := newBoundService(t, h.service.cfg)
	must(t, s2.Close(), "Close(S2): the bound Service is CLOSED, so a selection would refuse")
	p := testPeerForService(h.service, "remote", 3)
	for height := uint64(1); height <= 2; height++ {
		_, err := p.processRelayedBlock(blockAtHeight(t, source, height))
		must(t, err, "processRelayedBlock")
	}
	f.requireRetained(commit, "count 1 after two lease-path decreases")
	_, err := p.processRelayedBlock(blockAtHeight(t, source, 3))
	must(t, err, "processRelayedBlock(3)")
	f.requireAbsent(commit, "the lease path decreased although the binding names a CLOSED Service")
}

// TestDATTLCallbackEndToEndPanicReleasesLease pins H3 at the entry: a panic inside the decrease
// passed to the bound Service's registered entry propagates unrecovered, the lease is released
// exactly once before propagation, and Close then returns.
func TestDATTLCallbackEndToEndPanicReleasesLease(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	recovered := func() (value any) {
		defer func() { value = recover() }()
		_ = h.service.EnterDATTLMutation(func() error { panic("ttl body panic") })
		return nil
	}()
	require(t, recovered == "ttl body panic", "panic value=%v, want the original propagated unrecovered", recovered)
	require(t, h.service.closeReturnsWithin(lifecycleWatchdog), "Close stranded after the panicking entry")
}

// TestDATTLCallbackEndToEndNonAcceptedResults pins R1 and the R2 rows end to end over the real
// SyncEngine, DA owner and Service, counting through the retained image: a valid side-branch block
// stored non-canonical (D1), a KNOWN_BLOCK_NOOP replay and a DisconnectTip decrease nothing, so the
// record retained at count 3 survives the next two counted publications and expires only at the
// third. The side block enters through SyncEngine.ApplyBlockWithReorg (no Service lease).
func TestDATTLCallbackEndToEndNonAcceptedResults(t *testing.T) {
	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	fork := newTestHarness(t, 1, "127.0.0.1:0", nil)
	fork.timestamp += 1000
	sideBlock := fork.mineNextBlockBytes(t)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := testPeerForService(h.service, "remote", 5)
	relay := func(height uint64) {
		t.Helper()
		summary, err := p.processRelayedBlock(blockAtHeight(t, source, height))
		require(t, err == nil && summary != nil, "processRelayedBlock(%d)=(%+v,%v)", height, summary, err)
	}
	relay(1)
	relay(2)
	f := newDAIngressFixture(t, h)
	commit := f.commit(daRelayTestID(0xd3), 2)
	must(t, daRelayTestPeer(h, "127.0.0.1:19111", "127.0.0.1:19111").handleTx(commit), "retain the commit at count 3")
	summary, err := h.syncEngine.ApplyBlockWithReorg(sideBlock, nil)
	require(t, err == nil && summary != nil && len(summary.CanonicalAppliedBlocks) == 0 && h.chainState.Height == 2, "side block=(%+v,%v) height=%d, want stored non-canonical", summary, err, h.chainState.Height)
	summary, err = p.processRelayedBlock(blockAtHeight(t, source, 2))
	require(t, err == nil && summary == nil, "known block replay=(%+v,%v), want KNOWN_BLOCK_NOOP", summary, err)
	relay(3)
	disconnected, err := h.syncEngine.DisconnectTip()
	require(t, err == nil && disconnected != nil && h.chainState.Height == 2, "DisconnectTip=(%+v,%v)", disconnected, err)
	reconnected, err := h.syncEngine.ApplyBlock(blockAtHeight(t, source, 3), nil)
	require(t, err == nil && reconnected != nil, "reconnect(3)=(%+v,%v)", reconnected, err)
	f.requireRetained(commit, "count 1: two counted publications after the side block, replay and disconnect")
	relay(4)
	f.requireAbsent(commit, "the record the third counted publication expired")
}

// TestDATTLCallbackEndToEndStoredSideBlockThroughPeer pins the stored non-canonical row on the
// peer's lease path: a valid side-branch block relayed by a peer is stored non-canonical and
// decreases nothing, so the commit retained at count 3 survives the next two counted
// publications and expires only at the third.
func TestDATTLCallbackEndToEndStoredSideBlockThroughPeer(t *testing.T) {
	source := newTestHarness(t, 6, "127.0.0.1:0", nil)
	fork := newTestHarness(t, 1, "127.0.0.1:0", nil)
	fork.timestamp += 1000
	sideBlock := fork.mineNextBlockBytes(t)
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	p := testPeerForService(h.service, "remote", 5)
	relay := func(height uint64) {
		t.Helper()
		summary, err := p.processRelayedBlock(blockAtHeight(t, source, height))
		require(t, err == nil && summary != nil, "processRelayedBlock(%d)=(%+v,%v)", height, summary, err)
	}
	relay(1)
	relay(2)
	f := newDAIngressFixture(t, h)
	commit := f.commit(daRelayTestID(0xd4), 2)
	must(t, daRelayTestPeer(h, "127.0.0.1:19111", "127.0.0.1:19111").handleTx(commit), "retain the commit at count 3")
	_, err := p.processRelayedBlock(sideBlock)
	must(t, err, "processRelayedBlock(side block)")
	sideHash, err := consensus.BlockHash(sideBlock[:consensus.BLOCK_HEADER_BYTES])
	must(t, err, "BlockHash(side block)")
	stored, err := h.blockStore.GetBlockByHash(sideHash)
	require(t, err == nil && bytes.Equal(stored, sideBlock) && h.chainState.Height == 2 && h.chainState.TipHash != sideHash, "side block stored=%v err=%v height=%d, want stored non-canonical", stored != nil, err, h.chainState.Height)
	relay(3)
	relay(4)
	f.requireRetained(commit, "count 1: two counted publications after the stored side block")
	relay(5)
	f.requireAbsent(commit, "the record the third counted publication expired")
}
