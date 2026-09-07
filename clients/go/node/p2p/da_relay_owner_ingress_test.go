package p2p

import (
	"bytes"
	"crypto/sha3"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// require fails the test with the formatted message unless ok holds.
func require(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

// daIngressFixture funds and signs the DA transactions the remote ingress rows
// admit: AdmitDA is the only retained-member writer, so every member needs a real
// confirmed input (one seeded P2PK output), a real signature and its own nonce.
type daIngressFixture struct {
	t       *testing.T
	h       *testHarness
	signer  *consensus.MLDSA87Keypair
	address []byte
	next    uint64
	lastOp  consensus.Outpoint
}

type daTxSpec struct {
	kind       uint8
	daID       [32]byte
	chunkCount uint16
	index      uint16
	payload    []byte
	chunkHash  [32]byte
	commitment [][]byte
	fee        uint64
}

func newDAIngressFixture(t *testing.T, h *testHarness) *daIngressFixture {
	t.Helper()
	signer := mustP2PMLDSA87Keypair(t)
	return &daIngressFixture{t: t, h: h, signer: signer, address: consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())}
}

// op seeds and hands out the next spendable fixture outpoint.
func (f *daIngressFixture) op() consensus.Outpoint {
	f.next++
	op := consensus.Outpoint{Txid: [32]byte{0xda, byte(f.next >> 8), byte(f.next)}}
	f.h.chainState.Utxos[op] = consensus.UtxoEntry{Value: 1_000_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...)}
	f.lastOp = op
	return op
}

// tx builds one signed DA transaction: a commit carries the single CORE_DA_COMMIT
// output the renderer requires unless spec.commitment overrides the output list,
// a chunk the payload's SHA3-256 hash unless spec.chunkHash overrides it.
func (f *daIngressFixture) tx(spec daTxSpec) []byte {
	f.t.Helper()
	op, fee := f.op(), spec.fee
	if fee == 0 {
		fee = 100_000
	}
	tx := &consensus.Tx{
		Version: 1, TxKind: spec.kind, TxNonce: f.next,
		Inputs:    []consensus.TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout}},
		Outputs:   []consensus.TxOutput{{Value: 1_000_000 - fee, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), f.address...)}},
		DaPayload: append([]byte(nil), spec.payload...),
	}
	if spec.kind == 0x01 {
		commitment := sha3.Sum256(spec.daID[:])
		outputs := [][]byte{commitment[:]}
		if spec.commitment != nil {
			outputs = spec.commitment
		}
		for _, data := range outputs {
			tx.Outputs = append(tx.Outputs, consensus.TxOutput{CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: append([]byte(nil), data...)})
		}
		if len(spec.payload) == 0 {
			tx.DaPayload = []byte("manifest")
		}
		tx.DaCommitCore = &consensus.DaCommitCore{DaID: spec.daID, ChunkCount: spec.chunkCount, BatchNumber: 1}
	} else {
		hash := sha3.Sum256(spec.payload)
		if spec.chunkHash != ([32]byte{}) {
			hash = spec.chunkHash
		}
		tx.DaChunkCore = &consensus.DaChunkCore{DaID: spec.daID, ChunkIndex: spec.index, ChunkHash: hash}
	}
	return resignDATx(f.t, f, tx)
}

// commit declares chunkCount chunks; every row retains fewer, keeping the set incomplete.
func (f *daIngressFixture) commit(daID [32]byte, chunkCount uint16) []byte {
	return f.tx(daTxSpec{kind: 0x01, daID: daID, chunkCount: chunkCount})
}

func (f *daIngressFixture) chunk(daID [32]byte, index uint16, payload []byte) []byte {
	return f.tx(daTxSpec{kind: 0x02, daID: daID, index: index, payload: payload})
}

// probe classifies raw through the exported AdmitDA under a probe provenance: an exact
// replay is the mutation-free DUPLICATE (presence); absence readmits, so on a fresh da_id.
func (f *daIngressFixture) probe(raw []byte) (node.DAAdmissionResult, error) {
	f.t.Helper()
	provenance, err := node.NewPeerDAProvenance("probe-peer", "probe")
	must(f.t, err, "NewPeerDAProvenance")
	return f.h.service.daRelay.AdmitDA(raw, provenance)
}

func (f *daIngressFixture) requireRetained(raw []byte, label string) {
	f.t.Helper()
	got, err := f.probe(raw)
	require(f.t, err == nil && got.Disposition == node.DAAdmissionDuplicate, "%s: replay=(%+v,%v), want the retained member's DUPLICATE", label, got, err)
}

// requireAbsent readmits raw and expects RETAINED: the member was not retained.
func (f *daIngressFixture) requireAbsent(raw []byte, label string) {
	f.t.Helper()
	got, err := f.probe(raw)
	require(f.t, err == nil && got.Disposition == node.DAAdmissionRetained, "%s: readmit=(%+v,%v), want RETAINED", label, got, err)
}

// requireSuppressed asserts the Section 5.3 hit on a probe result: the zero result, TxAdmitUnavailable, the exact suppression message.
func requireSuppressed(t *testing.T, got node.DAAdmissionResult, err error, label string) {
	t.Helper()
	var admit *node.TxAdmitError
	require(t, got == node.DAAdmissionResult{} && errors.As(err, &admit) && admit.Kind == node.TxAdmitUnavailable && admit.Message == "DA repeated stable rejection suppressed", "%s: probe=(%+v,%v), want the zero result with TxAdmitUnavailable \"DA repeated stable rejection suppressed\"", label, got, err)
}

// admit retains raw through the production entry with PEER provenance for peer.
func (f *daIngressFixture) admit(raw []byte, peer string) {
	f.t.Helper()
	provenance, err := node.NewPeerDAProvenance(peer, peerQuotaKey(peer))
	must(f.t, err, "NewPeerDAProvenance")
	got, err := f.h.service.daRelay.AdmitDA(raw, provenance)
	require(f.t, err == nil && got.Disposition == node.DAAdmissionRetained, "AdmitDA=(%+v,%v), want RETAINED", got, err)
}

func mustTxID(t *testing.T, raw []byte) [32]byte {
	t.Helper()
	txid, err := canonicalTxID(raw)
	must(t, err, "canonicalTxID")
	return txid
}

func mustParseP2PTx(t *testing.T, raw []byte) *consensus.Tx {
	t.Helper()
	tx, _, err := parseCanonicalTx(append([]byte(nil), raw...)) // the parse aliases its input
	must(t, err, "parseCanonicalTx")
	return tx
}

// resignDATx signs tx with the fixture key: the same core keeps its txid, the
// fresh randomized signature gives different bytes and wtxid.
func resignDATx(t *testing.T, f *daIngressFixture, tx *consensus.Tx) []byte {
	t.Helper()
	must(t, consensus.SignTransaction(tx, f.h.chainState.Utxos, node.DevnetGenesisChainID(), f.signer), "SignTransaction")
	return mustMarshalPeerRuntimeTx(t, tx)
}

func nowCalls(h *testHarness) *atomic.Int32 { // scheduleDAPrefetch calls cfg.Now once per entry: the scheduler-attempt oracle
	var calls atomic.Int32
	inner := h.service.cfg.Now
	h.service.cfg.Now = func() time.Time { calls.Add(1); return inner() }
	return &calls
}

func peerQuality(p *peer) (uint8, uint64) {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.qualityScore, p.qualityHeight
}

func quotaKeyFree(s *Service, key string) bool {
	s.peerQuotaLocksMu.Lock()
	defer s.peerQuotaLocksMu.Unlock()
	return s.peerQuotaLocks[key] == nil
}

type peerEffects struct {
	ban    int
	last   string
	score  uint8
	anchor uint64
}

func effectsOf(p *peer) peerEffects {
	state := p.snapshotState()
	score, anchor := peerQuality(p)
	return peerEffects{state.BanScore, state.LastError, score, anchor}
}

// highTipHarness publishes the chainstate at height before the mempool binds, so LocalTipHeight
// reads height while admission stays coherent with the owner's stable tip (no headers needed).
func highTipHarness(t *testing.T, height uint64) *testHarness {
	t.Helper()
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	chainState := node.NewChainState()
	blockStore, err := node.CreateBlockStore(node.BlockStorePath(t.TempDir()))
	must(t, err, "CreateBlockStore")
	engine, err := node.NewSyncEngine(chainState, blockStore, h.syncCfg)
	must(t, err, "NewSyncEngine")
	_, err = engine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil)
	must(t, err, "ApplyBlock(genesis)")
	chainState.Height = height
	mempool, err := node.NewMempool(chainState, nil, node.DevnetGenesisChainID())
	must(t, err, "NewMempool")
	engine.SetMempool(mempool)
	cfg := h.service.cfg
	cfg.SyncEngine, cfg.BlockStore = engine, blockStore
	service, err := NewService(cfg)
	must(t, err, "NewService")
	h.chainState, h.blockStore, h.syncEngine, h.mempool, h.service = chainState, blockStore, engine, mempool, service
	require(t, engine.LocalTipHeight() == height, "LocalTipHeight=%d, want %d", engine.LocalTipHeight(), height)
	return h
}

func frozenFlag(object map[string]any, key string) bool { // an optional frozen boolean or count; absent = false
	flag, _ := object[key].(bool)
	count, _ := object[key].(float64)
	return flag || count != 0
}

// frozenD00Cases returns every frozen case's `expect` object by id.
func frozenD00Cases(t *testing.T) map[string]map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "conformance", "fixtures", "protocol", "da_admission_expected_v1.json"))
	must(t, err, "read frozen D00 authority")
	var artifact struct {
		Cases []map[string]any `json:"cases"`
	}
	must(t, json.Unmarshal(raw, &artifact), "decode frozen D00 authority")
	require(t, len(artifact.Cases) == 79, "frozen authority carries %d cases, want 79", len(artifact.Cases))
	cases := make(map[string]map[string]any, len(artifact.Cases))
	for _, row := range artifact.Cases {
		cases[row["id"].(string)] = row["expect"].(map[string]any)
	}
	return cases
}

// The four disjoint D00 evidence sets of the contract and their union, its d00_in_scope_case_ids list;
// REMOTE_STANDARD_EXIT runs last so the single-frame relay probe is still live for every DA row.
var (
	d00PublicHandleTxIDs = []string{"REMOTE_COMMIT_RETAINED", "REMOTE_CHUNK_RETAINED", "REMOTE_EXACT_REPLAY", "REMOTE_OWNER_CONFLICT", "REMOTE_POLICY_REJECT", "REMOTE_EXACT_CHUNK_REPLAY", "REMOTE_SAME_TXID_NONEXACT_VALID", "REMOTE_SAME_TXID_NONEXACT_INVALID", "REMOTE_EXACT_COMMIT_REPLAY_UNSOLICITED", "REMOTE_EXACT_CHUNK_REPLAY_UNSOLICITED", "REMOTE_REPLAY_EVIDENCE_ABSENT", "REMOTE_STANDARD_EXIT"}
	d00CleanupIDs        = []string{"STATE_B_PEER_CHUNK_CLEANUP_PRESERVES_NONPEER", "STATE_B_PEER_COMMIT_CLEANUP_PROTECTED"}
	d00InternalIDs       = []string{"REMOTE_REPLAY_EVIDENCE_UNAVAILABLE", "REMOTE_REPLAY_EVIDENCE_DANGLING", "REMOTE_REPLAY_EVIDENCE_CORRUPT", "REMOTE_REPLAY_EVIDENCE_MISMATCH", "REMOTE_REPLAY_EVIDENCE_UNSTABLE"}
	d00CanonicalIDs      = []string{"REMOTE_REPLAY_D1_REMOVAL_FIRST", "REMOTE_REPLAY_D1_SNAPSHOT_FIRST"}
	d00InScopeIDs        = []string{"REMOTE_STANDARD_EXIT", "REMOTE_COMMIT_RETAINED", "REMOTE_CHUNK_RETAINED", "REMOTE_EXACT_REPLAY", "REMOTE_OWNER_CONFLICT", "REMOTE_POLICY_REJECT", "STATE_B_PEER_CHUNK_CLEANUP_PRESERVES_NONPEER", "STATE_B_PEER_COMMIT_CLEANUP_PROTECTED", "REMOTE_EXACT_CHUNK_REPLAY", "REMOTE_SAME_TXID_NONEXACT_VALID", "REMOTE_SAME_TXID_NONEXACT_INVALID", "REMOTE_EXACT_COMMIT_REPLAY_UNSOLICITED", "REMOTE_EXACT_CHUNK_REPLAY_UNSOLICITED", "REMOTE_REPLAY_EVIDENCE_ABSENT", "REMOTE_REPLAY_EVIDENCE_UNAVAILABLE", "REMOTE_REPLAY_EVIDENCE_DANGLING", "REMOTE_REPLAY_EVIDENCE_CORRUPT", "REMOTE_REPLAY_EVIDENCE_MISMATCH", "REMOTE_REPLAY_EVIDENCE_UNSTABLE", "REMOTE_REPLAY_D1_REMOVAL_FIRST", "REMOTE_REPLAY_D1_SNAPSHOT_FIRST"}
)

// TestRemoteDAExitsBeforeEveryStandardAuthority: remote DA members are retained without reaching
// the seen-set, the canonical pool (its AddTx is the metadata producer under this wiring), MSG_TX
// or the four admission counters (R8); a standard tx reaches each once and counts one Accepted.
func TestRemoteDAExitsBeforeEveryStandardAuthority(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	mempool := wireCanonicalMempoolForP2PTest(t, h)
	f := newDAIngressFixture(t, h)
	p := daRelayTestPeer(h, "127.0.0.1:19111")
	frames, closeProbe := registerRelayFrameProbe(t, h.service, "127.0.0.1:19119")
	defer closeProbe()
	calls := nowCalls(h)
	daID, counters := daRelayTestID(0x10), mempool.AdmissionCounts()
	for label, raw := range map[string][]byte{"commit": f.commit(daID, 2), "chunk": f.chunk(daID, 0, []byte("da-exit"))} {
		txid := mustTxID(t, raw)
		must(t, p.handleTx(raw), "handleTx("+label+")")
		require(t, !h.service.txSeen.Has(txid) && !mempool.Contains(txid) && mempool.AdmissionCounts() == counters, "remote DA %s reached a standard authority: seen=%v pooled=%v counters=%+v (before %+v)", label, h.service.txSeen.Has(txid), mempool.Contains(txid), mempool.AdmissionCounts(), counters)
		assertNoRelayFrame(t, frames, "remote DA "+label)
		f.requireRetained(raw, label)
	}
	require(t, calls.Load() == 2, "scheduler entries after two retained members=%d, want 2", calls.Load())
	standard, txid, _ := signedCanonicalP2PTxForHarness(t, h, 9411)
	must(t, p.handleTx(standard), "handleTx(standard)")
	frame := <-frames
	counters.Accepted++
	require(t, h.service.txSeen.Has(txid) && mempool.Contains(txid) && frame.Command == messageInv && calls.Load() == 2 && mempool.AdmissionCounts() == counters, "standard path seen=%v pooled=%v command=%q scheduler entries=%d counters=%+v (want %+v), want the DA assertions non-vacuous", h.service.txSeen.Has(txid), mempool.Contains(txid), frame.Command, calls.Load(), mempool.AdmissionCounts(), counters)
}

// TestRemoteDAResultEffects executes every result row of the remote DA arm on real signed
// bytes through handleTx: the complete peer tuple, scheduler-entry count and retained image.
func TestRemoteDAResultEffects(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	p, other := daRelayTestPeer(h, "127.0.0.1:19111"), daRelayTestPeer(h, "127.0.0.2:19112")
	calls := nowCalls(h)
	daID := daRelayTestID(0x20)
	commit, chunk := f.commit(daID, 2), f.chunk(daID, 0, []byte("payload-0"))
	run := func(label string, peer *peer, raw []byte, wantErr error, wantCalls int32, check func(before, after peerEffects)) {
		t.Helper()
		before := effectsOf(peer)
		calls.Store(0)
		err := peer.handleTx(raw)
		require(t, err == wantErr, "%s: handleTx=%v, want exactly %v", label, err, wantErr) //nolint:errorlint // HASH_FAILURE returns the sentinel itself at the threshold, never a wrapper; every other row is nil.
		require(t, calls.Load() == wantCalls, "%s: scheduler entries=%d, want %d", label, calls.Load(), wantCalls)
		check(before, effectsOf(peer))
	}
	same := func(before, after peerEffects) {
		t.Helper()
		require(t, after == before, "peer effects moved: %+v -> %+v", before, after)
	}
	banned := func(want string) func(before, after peerEffects) {
		return func(before, after peerEffects) {
			t.Helper()
			require(t, after == peerEffects{before.ban + 10, want, before.score, before.anchor}, "peer effects=%+v, want ban +10 and LastError %q with quality unchanged (before %+v)", after, want, before)
		}
	}
	// INITIAL_INVALID: the trailing byte fails the canonical parse before any DA effect.
	trailing := append(append([]byte(nil), commit...), 0x00)
	run("INITIAL_INVALID trailing byte", p, trailing, nil, 0, banned("non-canonical tx bytes"))
	_, err := f.probe(trailing)
	require(t, err != nil, "the non-canonical bytes were retained")
	// RETAINED: one scheduler entry per member; EXACT_REPLAY / SAME_TXID_NONEXACT (valid) /
	// OCCUPIED_CHUNK_INDEX: neutral DUPLICATEs.
	run("RETAINED commit", p, commit, nil, 1, same)
	run("RETAINED chunk", p, chunk, nil, 1, same)
	run("EXACT_REPLAY commit", p, commit, nil, 0, same)
	run("EXACT_REPLAY chunk from another peer", other, chunk, nil, 0, same)
	alternate := resignDATx(t, f, mustParseP2PTx(t, chunk))
	require(t, mustTxID(t, alternate) == mustTxID(t, chunk) && !bytes.Equal(alternate, chunk), "the alternate signature did not keep the txid with different bytes")
	run("SAME_TXID_NONEXACT valid", p, alternate, nil, 0, same)
	f.requireRetained(chunk, "retained chunk after the nonexact replay")
	run("OCCUPIED_CHUNK_INDEX", other, f.chunk(daID, 0, []byte("payload-0")), nil, 0, same)
	// DISTINCT_COMMIT: every separately validated competing commit applies COMPETING_SCORE_V1
	// once — at local height 0 the grace delta 1 — to this exact peer and nothing else.
	competitor := f.commit(daID, 2)
	graceStep := func(before, after peerEffects) {
		t.Helper()
		require(t, after == peerEffects{before.ban, before.last, before.score - 1, before.anchor}, "competing commit effects=%+v, want one grace step only (before %+v)", after, before)
	}
	run("DISTINCT_COMMIT", other, competitor, nil, 0, graceStep)
	run("DISTINCT_COMMIT repeated unretained competitor", other, competitor, nil, 0, graceStep)
	run("EXACT_REPLAY after the conflict", p, commit, nil, 0, same)
	_, err = f.probe(competitor)
	must(t, err, "competitor probe")
	f.requireRetained(commit, "the first-seen commit after the competitor")
	// HASH_FAILURE: the only peer fault; LastError is the sentinel text, the sentinel itself
	// is returned at the ban threshold, nothing is retained.
	bad := f.tx(daTxSpec{kind: 0x02, daID: daRelayTestID(0x21), payload: []byte("bad"), chunkHash: [32]byte{0xff}})
	run("HASH_FAILURE below threshold", p, bad, nil, 0, banned("da chunk hash mismatch"))
	h.service.cfg.PeerRuntimeConfig.BanThreshold = effectsOf(p).ban + 10
	run("HASH_FAILURE at threshold", p, bad, node.ErrDARelayChunkHashMismatch, 0, banned("da chunk hash mismatch"))
	h.service.cfg.PeerRuntimeConfig.BanThreshold = 1000
	_, err = f.probe(bad)
	require(t, err != nil, "the bad-hash chunk was retained")
	// OTHER_ADMIT_ERROR: owner, validation and renderer refusals are peer-neutral, schedule
	// nothing and retain nothing; each carries the zero result.
	unfunded := f.chunk(daRelayTestID(0x22), 0, []byte("unfunded"))
	delete(h.chainState.Utxos, f.lastOp)
	for label, raw := range map[string][]byte{
		"missing utxo":                unfunded,
		"zero CORE_DA_COMMIT outputs": f.tx(daTxSpec{kind: 0x01, daID: daRelayTestID(0x25), chunkCount: 2, commitment: [][]byte{}}),
		"two CORE_DA_COMMIT outputs":  f.tx(daTxSpec{kind: 0x01, daID: daRelayTestID(0x26), chunkCount: 2, commitment: [][]byte{make([]byte, 32), make([]byte, 32)}}),
		"31-byte CORE_DA_COMMIT":      f.tx(daTxSpec{kind: 0x01, daID: daRelayTestID(0x27), chunkCount: 2, commitment: [][]byte{make([]byte, 31)}}),
		"33-byte CORE_DA_COMMIT":      f.tx(daTxSpec{kind: 0x01, daID: daRelayTestID(0x28), chunkCount: 2, commitment: [][]byte{make([]byte, 33)}}),
	} {
		run("OTHER_ADMIT_ERROR "+label, p, raw, nil, 0, same)
		got, err := f.probe(raw)
		require(t, err != nil && got == node.DAAdmissionResult{}, "OTHER_ADMIT_ERROR %s: probe=(%+v,%v), want a zero result with the owning error", label, got, err)
	}
	// COMPLETE_DEFERRED: the completing chunk keeps the exact temporary guard, schedules
	// nothing and leaves no complete candidate; a second delivery refuses again.
	deferredID := daRelayTestID(0x29)
	run("RETAINED single-chunk commit", p, f.commit(deferredID, 1), nil, 1, same)
	completing := f.chunk(deferredID, 0, []byte("complete"))
	for i := 0; i < 2; i++ {
		run(fmt.Sprintf("COMPLETE_DEFERRED delivery %d", i), p, completing, nil, 0, same)
	}
	_, err = f.probe(completing)
	require(t, err != nil && err.Error() == "DA COMPLETE_SET capacity owner is not active" && len(h.service.CompleteDASetCandidates(^uint64(0))) == 0, "COMPLETE_DEFERRED probe err=%v candidates=%d", err, len(h.service.CompleteDASetCandidates(^uint64(0))))
	// ALREADY_TERMINAL on a genuinely latched engine: bounded completion, the quota key free,
	// no AdmitDA and no peer effect; malformed bytes and an over-bound identity keep their
	// earlier refusals ahead of the latch check.
	lh := latchedDAHarness(t, newTestHarness(t, 2, "127.0.0.1:0", nil))
	lf := newDAIngressFixture(t, lh)
	lp, wide := daRelayTestPeer(lh, "127.0.0.1:19113"), daRelayTestPeer(lh, strings.Repeat("a", 255)+":12345678")
	latchedCommit, latchedCalls := lf.commit(daRelayTestID(0x2a), 2), nowCalls(lh)
	for label, row := range map[string]struct {
		peer  *peer
		raw   []byte
		check func(before, after peerEffects)
	}{
		"valid DA on the latch":            {lp, latchedCommit, same},
		"malformed bytes on the latch":     {lp, append(append([]byte(nil), latchedCommit...), 0x00), banned("non-canonical tx bytes")},
		"over-bound identity on the latch": {wide, latchedCommit, same},
	} {
		done, before := make(chan error, 1), effectsOf(row.peer)
		go func() { done <- row.peer.handleTx(row.raw) }()
		requireReturned(t, done, label+": handleTx on the latched engine")
		row.check(before, effectsOf(row.peer))
		require(t, quotaKeyFree(lh.service, peerQuotaKey(row.peer.addr())) && latchedCalls.Load() == 0, "%s: quota key held or scheduler entries=%d", label, latchedCalls.Load())
	}
	// REJECTED_REPEAT on a fresh harness and owner (RUBIN_COMPACT_BLOCKS.md Section 5.3): the first
	// invalid-signature entry through handleTx is peer-neutral, touches no standard authority and
	// populates the owner-wide suppression state; the probe then hits it under another peer identity,
	// a second entry stays neutral, and the untouched valid representation (same txid, different
	// wtxid) admits normally while the invalid bytes stay suppressed; a closing standard tx proves the untouched authorities live.
	rh := newTestHarness(t, 1, "127.0.0.1:0", nil)
	rmempool, rf, rp := wireCanonicalMempoolForP2PTest(t, rh), newDAIngressFixture(t, rh), daRelayTestPeer(rh, "127.0.0.1:19114")
	rframes, _ := registerRelayFrameProbe(t, rh.service, "127.0.0.1:19119")
	calls = nowCalls(rh)
	valid := rf.commit(daRelayTestID(0x2b), 2)
	corrupted := mustParseP2PTx(t, valid)
	corrupted.Witness[0].Signature[0] ^= 0xff
	invalid := mustMarshalPeerRuntimeTx(t, corrupted)
	_, validTxID, validWTxID, _, err := consensus.ParseTx(valid)
	must(t, err, "ParseTx(valid)")
	_, txid, wtxid, consumed, err := consensus.ParseTx(invalid)
	must(t, err, "ParseTx(invalid)")
	require(t, consumed == len(invalid) && txid == validTxID && wtxid != validWTxID, "the corrupted signature is not a canonical tx with the same txid and a different wtxid: consumed=%d of %d, same txid=%v, same wtxid=%v", consumed, len(invalid), txid == validTxID, wtxid == validWTxID)
	counters := rmempool.AdmissionCounts()
	untouched := func(label string) {
		t.Helper()
		require(t, !rh.service.txSeen.Has(txid) && !rmempool.Contains(txid) && rmempool.AdmissionCounts() == counters, "%s: reached a standard authority: seen=%v pooled=%v counters=%+v (before %+v)", label, rh.service.txSeen.Has(txid), rmempool.Contains(txid), rmempool.AdmissionCounts(), counters)
		assertNoRelayFrame(t, rframes, label)
	}
	suppressed := func(label string) {
		t.Helper()
		got, err := rf.probe(invalid)
		requireSuppressed(t, got, err, label)
	}
	run("REJECTED_REPEAT first entry", rp, invalid, nil, 0, same)
	suppressed("REJECTED_REPEAT probe after the first entry")
	untouched("REJECTED_REPEAT first entry and probe")
	run("REJECTED_REPEAT second entry", rp, invalid, nil, 0, same)
	untouched("REJECTED_REPEAT second entry")
	run("REJECTED_REPEAT valid representation", rp, valid, nil, 1, same)
	suppressed("REJECTED_REPEAT probe after the valid representation")
	rf.requireRetained(valid, "the valid representation after its suppressed invalid witness")
	standard, stxid, _ := signedCanonicalP2PTxForHarness(t, rh, 9413)
	must(t, rp.handleTx(standard), "handleTx(standard)")
	counters.Accepted++
	require(t, rh.service.txSeen.Has(stxid) && rmempool.Contains(stxid) && (<-rframes).Command == messageInv && rmempool.AdmissionCounts() == counters, "REJECTED_REPEAT standard control: seen=%v pooled=%v counters=%+v (want %+v), want every untouched authority live", rh.service.txSeen.Has(stxid), rmempool.Contains(stxid), rmempool.AdmissionCounts(), counters)
}

// TestRemoteDAIdentityBoundsPrecedeAdmission pins IDENTITY_BOUNDS_V1 at both limits
// and one over, and the per-quota serialization on the captured address's key.
func TestRemoteDAIdentityBoundsPrecedeAdmission(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	f := newDAIngressFixture(t, h)
	calls := nowCalls(h)
	for i, row := range []struct {
		addr     string
		admitted bool
	}{
		{"", false},
		{strings.Repeat("a", 255) + ":1234567", true},   // 263 bytes, quota 255
		{strings.Repeat("a", 255) + ":12345678", false}, // 264 bytes, quota 255
		{strings.Repeat("b", 255) + ":1", true},         // 257 bytes, quota 255
		{strings.Repeat("b", 256) + ":1", false},        // 258 bytes, quota 256
	} {
		p := daRelayTestPeer(h, row.addr)
		raw := f.commit(daRelayTestID(0x30+byte(i)), 2)
		before := effectsOf(p)
		calls.Store(0)
		must(t, p.handleTx(raw), fmt.Sprintf("addr %d bytes: handleTx", len(row.addr)))
		require(t, effectsOf(p) == before, "addr %d bytes: peer effects moved %+v -> %+v", len(row.addr), before, effectsOf(p))
		require(t, calls.Load() == map[bool]int32{true: 1}[row.admitted], "addr %d bytes: scheduler entries=%d, admitted=%v", len(row.addr), calls.Load(), row.admitted)
		if row.admitted {
			f.requireRetained(raw, fmt.Sprintf("addr %d bytes", len(row.addr)))
		} else {
			f.requireAbsent(raw, fmt.Sprintf("addr %d bytes", len(row.addr)))
		}
	}
	// A held quota key parks the handler with nothing retained, a different key proceeds,
	// and the parked admission's scheduler callback observes its key already released.
	addr, otherAddr := "127.0.0.1:19140", "127.0.0.2:19141"
	held, free := f.commit(daRelayTestID(0x40), 2), f.commit(daRelayTestID(0x41), 2)
	unlock := h.service.lockPeerQuotaKey(peerQuotaKey(addr))
	blocked := make(chan error, 1)
	go func() { blocked <- daRelayTestPeer(h, addr).handleTx(held) }()
	waitForPeerQuotaLockRefs(t, h.service, peerQuotaKey(addr), 2)
	requireStillBlocked(t, blocked, "handleTx on a held quota key")
	inner := h.service.cfg.Now
	plans, _ := h.service.daRelay.PlanPrefetch(daRelayTestID(0x40), []string{"probe"}, inner())
	require(t, len(plans) == 0, "the retained image moved while the admission's quota key was held")
	freed := make(chan error, 1)
	go func() { freed <- daRelayTestPeer(h, otherAddr).handleTx(free) }()
	requireReturned(t, freed, "handleTx on a different quota key")
	releasedInScheduler := make(chan bool, 1)
	h.service.cfg.Now = func() time.Time { releasedInScheduler <- quotaKeyFree(h.service, peerQuotaKey(addr)); return inner() }
	unlock()
	requireReturned(t, blocked, "handleTx after its quota key was released")
	f.requireRetained(held, "held-key member")
	f.requireRetained(free, "free-key member")
	require(t, <-releasedInScheduler, "the scheduler ran while the admission's quota key was still held")
}

// TestRemoteD00ReachableCutoverCases pins the evidence-set partition of the 21 IDs, then
// executes the twelve public IDs through handleTx against the frozen artifact.
func TestRemoteD00ReachableCutoverCases(t *testing.T) {
	cases := frozenD00Cases(t)
	seen := map[string]int{}
	for _, set := range [][]string{d00PublicHandleTxIDs, d00CleanupIDs, d00InternalIDs, d00CanonicalIDs} {
		for _, id := range set {
			seen[id]++
		}
	}
	for _, id := range d00InScopeIDs {
		require(t, seen[id] == 1 && cases[id] != nil, "%s: owned by %d evidence sets (want 1), frozen=%v", id, seen[id], cases[id] != nil)
	}
	require(t, len(seen) == 21 && len(d00InScopeIDs) == 21, "evidence sets name %d IDs, contract lists %d, want 21", len(seen), len(d00InScopeIDs))
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	mempool := wireCanonicalMempoolForP2PTest(t, h)
	f := newDAIngressFixture(t, h)
	p, stranger := daRelayTestPeer(h, "127.0.0.1:19111"), daRelayTestPeer(h, "127.0.0.3:19118")
	frames, closeProbe := registerRelayFrameProbe(t, h.service, "127.0.0.1:19119")
	defer closeProbe()
	calls := nowCalls(h)
	daID := daRelayTestID(0x50)
	commit, chunk := f.commit(daID, 2), f.chunk(daID, 0, []byte("d00-chunk"))
	conflictOp := f.op()
	must(t, mempool.AddTx(mustBuildSignedP2PTx(t, h.chainState.Utxos, []consensus.Outpoint{conflictOp}, 100_000, 100_000, 9511, f.signer, f.address, f.address)), "standard claim on the conflicting input")
	conflicting := mustParseP2PTx(t, f.tx(daTxSpec{kind: 0x01, daID: daRelayTestID(0x51), chunkCount: 2}))
	conflicting.Inputs = []consensus.TxInput{{PrevTxid: conflictOp.Txid, PrevVout: conflictOp.Vout}} // rebuilt on the standard claim's exact input
	standardExit, _, _ := signedCanonicalP2PTxForHarness(t, h, 9512)
	corrupt := mustParseP2PTx(t, commit) // one flipped signature byte: the same txid, a rejected signature
	corrupt.Witness[0].Signature[0] ^= 0xff
	counters := mempool.AdmissionCounts()
	rows := map[string]struct {
		peer *peer
		raw  []byte
	}{
		"REMOTE_STANDARD_EXIT":                   {p, standardExit},
		"REMOTE_COMMIT_RETAINED":                 {p, commit},
		"REMOTE_CHUNK_RETAINED":                  {p, chunk},
		"REMOTE_EXACT_REPLAY":                    {p, commit},
		"REMOTE_EXACT_CHUNK_REPLAY":              {p, chunk},
		"REMOTE_EXACT_COMMIT_REPLAY_UNSOLICITED": {stranger, commit},
		"REMOTE_EXACT_CHUNK_REPLAY_UNSOLICITED":  {stranger, chunk},
		"REMOTE_SAME_TXID_NONEXACT_VALID":        {p, resignDATx(t, f, mustParseP2PTx(t, commit))},
		"REMOTE_SAME_TXID_NONEXACT_INVALID":      {p, mustMarshalPeerRuntimeTx(t, corrupt)},
		"REMOTE_OWNER_CONFLICT":                  {p, resignDATx(t, f, conflicting)},
		"REMOTE_POLICY_REJECT":                   {p, f.tx(daTxSpec{kind: 0x01, daID: daRelayTestID(0x52), chunkCount: 2, fee: 7})},
		"REMOTE_REPLAY_EVIDENCE_ABSENT":          {p, f.commit(daRelayTestID(0x53), 2)},
	}
	require(t, len(rows) == len(d00PublicHandleTxIDs), "rows=%d, want %d", len(rows), len(d00PublicHandleTxIDs))
	for _, id := range d00PublicHandleTxIDs {
		want, row := cases[id], rows[id]
		p2p, result := want["p2p_envelope"].(map[string]any), want["result"].(map[string]any)
		errorCode, _ := result["error_code"].(string)
		require(t, row.raw != nil, "%s has no row", id)
		txid, before := mustTxID(t, row.raw), effectsOf(row.peer)
		calls.Store(0)
		err := row.peer.handleTx(row.raw)
		require(t, err == nil && !frozenFlag(p2p, "replay_disconnect"), "%s: handleTx=%v, frozen replay_disconnect=%v", id, err, p2p["replay_disconnect"])
		require(t, p2p["peer_quality_effect"] == "UNCHANGED" && effectsOf(row.peer) == before, "%s: peer effects %+v -> %+v, frozen %v", id, before, effectsOf(row.peer), p2p["peer_quality_effect"])
		standardTouched := h.service.txSeen.Has(txid) || mempool.Contains(txid)
		require(t, frozenFlag(want, "standard_present") == standardTouched && !frozenFlag(p2p, "standard_fallback"), "%s: standard present=%v, frozen standard_present=%v standard_fallback=%v", id, standardTouched, want["standard_present"], p2p["standard_fallback"])
		if standardTouched {
			<-frames // the one MSG_TX announcement of the standard exit
			counters.Accepted++
		} else {
			assertNoRelayFrame(t, frames, id)
		}
		require(t, mempool.AdmissionCounts() == counters, "%s: admission counters=%+v, want %+v", id, mempool.AdmissionCounts(), counters)
		if standardTouched {
			continue
		}
		got, probeErr := f.probe(row.raw)
		retained := probeErr == nil && got.Disposition == node.DAAdmissionDuplicate
		switch p2p["disposition"] {
		case "RETAINED_INCOMPLETE":
			require(t, calls.Load() == 1 && retained, "%s: entries=%d probe=(%+v,%v), want one scheduler entry and a retained member", id, calls.Load(), got, probeErr)
		case "REJECTED":
			require(t, calls.Load() == 0 && !frozenFlag(p2p, "replay_inventory_publications"), "%s: entries=%d probe=(%+v,%v)", id, calls.Load(), got, probeErr)
			if errorCode != "" { // the PEER re-probe of the rejected bytes is the Section 5.3 hit; the frozen code is the same bytes' PEER miss on a fresh owner holding a copy of the spent input
				requireSuppressed(t, got, probeErr, id)
				fresh := newTestHarness(t, 2, "127.0.0.1:0", nil)
				in := mustParseP2PTx(t, row.raw).Inputs[0]
				op := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
				fresh.chainState.Utxos[op] = h.chainState.Utxos[op]
				missed, missErr := newDAIngressFixture(t, fresh).probe(row.raw)
				require(t, missErr != nil && strings.Contains(missErr.Error(), errorCode) && missed == node.DAAdmissionResult{}, "%s: fresh-owner PEER admission=(%+v,%v), frozen error_code %q", id, missed, missErr, errorCode)
			}
			replay := strings.HasPrefix(id, "REMOTE_EXACT") || id == "REMOTE_SAME_TXID_NONEXACT_VALID"
			require(t, retained == replay, "%s: retained=%v on a replay=%v row: probe=(%+v,%v)", id, retained, replay, got, probeErr)
		default:
			t.Fatalf("%s: frozen disposition %v is not a P2P disposition", id, p2p["disposition"])
		}
	}
}

// TestRemoteD00CleanupCases executes the two STATE_B cleanup IDs through unregisterPeer
// on the frozen before-images (peerless members via test-only AdmitDA provenances).
func TestRemoteD00CleanupCases(t *testing.T) {
	cases := frozenD00Cases(t)
	for _, row := range []struct {
		id         string
		peerCommit bool
		removed    bool
	}{
		{"STATE_B_PEER_CHUNK_CLEANUP_PRESERVES_NONPEER", false, true},
		{"STATE_B_PEER_COMMIT_CLEANUP_PROTECTED", true, false},
	} {
		t.Run(row.id, func(t *testing.T) {
			require(t, cases[row.id] != nil, "%s is not frozen", row.id)
			h := newTestHarness(t, 1, "127.0.0.1:0", nil)
			f := newDAIngressFixture(t, h)
			p := daRelayTestPeer(h, "127.0.0.1:19111")
			must(t, h.service.registerPeer(p), "registerPeer")
			daID := daRelayTestID(0x60)
			commit, chunk, detached := f.commit(daID, 3), f.chunk(daID, 0, []byte("chunk-0")), f.chunk(daID, 1, []byte("detached-chunk"))
			peerMember, localMember := chunk, commit
			if row.peerCommit {
				peerMember, localMember = commit, chunk
			}
			_, err := h.service.daRelay.AdmitDA(localMember, node.LocalDAProvenance())
			must(t, err, "LOCAL member")
			must(t, p.handleTx(peerMember), "PEER member")
			_, err = h.service.daRelay.AdmitDA(detached, node.DetachedReorgDAProvenance())
			must(t, err, "DETACHED_REORG chunk")
			h.service.unregisterPeer(p)
			f.requireRetained(localMember, "LOCAL member")
			f.requireRetained(detached, "DETACHED_REORG chunk")
			if row.removed {
				f.requireAbsent(peerMember, "REMOVED_PEER_CHUNKS: the PEER member")
			} else {
				f.requireRetained(peerMember, "NO_SELECTION: the PEER member")
			}
		})
	}
}

// TestRemoteD00CanonicalOrderingCases executes the two D1 ordering IDs: removal before
// the candidate's admission, and an exact snapshot completing before the removal.
func TestRemoteD00CanonicalOrderingCases(t *testing.T) {
	cases := frozenD00Cases(t)
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	for _, id := range d00CanonicalIDs {
		t.Run(id, func(t *testing.T) {
			p2p := cases[id]["p2p_envelope"].(map[string]any)
			require(t, p2p["peer_quality_effect"] == "UNCHANGED" && !frozenFlag(p2p, "replay_inventory_publications"), "%s: frozen envelope %+v", id, p2p)
			h := newTestHarness(t, 1, "127.0.0.1:0", nil)
			f := newDAIngressFixture(t, h)
			p := daRelayTestPeer(h, "127.0.0.1:19111")
			calls := nowCalls(h)
			commit := f.commit(daRelayTestID(0x70), 2)
			must(t, p.handleTx(commit), "retain the commit")
			commitOp := f.lastOp
			neutral := func(label string) {
				t.Helper()
				calls.Store(0)
				before := effectsOf(p)
				must(t, p.handleTx(commit), label)
				require(t, calls.Load() == 0 && effectsOf(p) == before, "%s: entries=%d effects %+v -> %+v", label, calls.Load(), before, effectsOf(p))
			}
			if id == "REMOTE_REPLAY_D1_SNAPSHOT_FIRST" {
				neutral("exact snapshot before removal")
			}
			// C1 no longer holds the commit's input, so the transition's D1 removes the record.
			delete(h.chainState.Utxos, commitOp)
			_, err := h.syncEngine.ApplyBlock(blockAtHeight(t, source, 1), nil)
			must(t, err, "ApplyBlock")
			neutral("admission after D1 removal")
			_, err = f.probe(commit)
			require(t, err != nil && strings.Contains(err.Error(), "TX_ERR_MISSING_UTXO") && len(h.service.CompleteDASetCandidates(^uint64(0))) == 0, "%s: post-removal probe err=%v, frozen error_code TX_ERR_MISSING_UTXO", id, err)
		})
	}
}

// TestRemoteDAPeerQualityPolicy pins COMPETING_SCORE_V1's literal arithmetic: real
// competing commits at the literal heights, then boundary rows on the score methods.
func TestRemoteDAPeerQualityPolicy(t *testing.T) {
	conflicts := func(height uint64, count int) (*peer, []byte) {
		t.Helper()
		h := highTipHarness(t, height)
		f := newDAIngressFixture(t, h)
		origin, rival := daRelayTestPeer(h, "127.0.0.1:19111"), daRelayTestPeer(h, "127.0.0.2:19112")
		daID := daRelayTestID(0x90)
		must(t, origin.handleTx(f.commit(daID, 2)), "first-seen commit")
		competitor := f.commit(daID, 2)
		for i := 0; i < count; i++ {
			must(t, rival.handleTx(competitor), fmt.Sprintf("conflict %d", i))
		}
		return rival, competitor
	}
	expect := func(label string, p *peer, score uint8, anchor uint64) {
		t.Helper()
		got, gotAnchor := peerQuality(p)
		require(t, got == score && gotAnchor == anchor, "%s: score=%d anchor=%d, want %d at %d", label, got, gotAnchor, score, anchor)
	}
	rival, _ := conflicts(1439, 1)
	expect("one conflict at height 1439", rival, 49, 1439)
	rival, _ = conflicts(1440, 1)
	expect("one conflict at height 1440", rival, 48, 1440)
	rival, competitor := conflicts(1440, 6)
	expect("six conflicts at height 1440", rival, 38, 1440)
	must(t, rival.handleTx(competitor), "the same unretained competitor again")
	expect("the repeated competitor", rival, 36, 1440)
	state := rival.snapshotState()
	require(t, state.BanScore == 0 && state.LastError == "", "competing commits touched BanScore/LastError: %+v", state)
	// Boundary rows on a bare peer, every expectation a contract literal.
	p := &peer{qualityScore: 38, qualityHeight: 1440}
	p.qualityPreferred(1583)
	expect("h1583 keeps the partial interval", p, 38, 1440)
	p.qualityPreferred(1584)
	expect("h1584 completes one interval", p, 39, 1584)
	p.qualityPreferred(1584)
	expect("a same-height reread", p, 39, 1584)
	p.qualityPreferred(1728)
	expect("h1728 completes the next interval", p, 40, 1728)
	p.qualityPreferred(1500)
	expect("a lower height never rewinds", p, 40, 1728)
	for _, height := range []uint64{39744, 9440064, 618475293504} { // 266 / 65546 / 4294967306 intervals: each narrows below 50 before the bound
		p.qualityScore, p.qualityHeight = 38, 1440
		p.qualityPreferred(height)
		expect(fmt.Sprintf("h%d saturates at 50 after bounding in uint64", height), p, 50, height)
	}
	p.qualityScore, p.qualityHeight = 38, 1440
	p.applyCompetingCommitScore(1728)
	expect("normalization precedes the subtraction on an interval boundary", p, 38, 1728)
	p.qualityScore, p.qualityHeight = 20, 2000
	p.applyCompetingCommitScore(100)
	expect("grace uses the current height even below a higher anchor", p, 19, 2000)
	p.qualityScore, p.qualityHeight = 1, 1440
	p.applyCompetingCommitScore(1440)
	expect("the subtraction saturates at zero", p, 0, 1440)
	p.applyCompetingCommitScore(1440)
	expect("a saturated score stays zero", p, 0, 1440)
	p.qualityScore, p.qualityHeight = 0, 1440
	require(t, p.qualityPreferred(^uint64(0)), "a normalized score of 50 must keep the preference")
	expect("a near-maximum height saturates at 50 without narrowing", p, 50, 18446744073709551600)
	p.qualityScore = 39
	require(t, !p.qualityPreferred(^uint64(0)), "score 39 must lose the preference")
	p.qualityScore = 40
	require(t, p.qualityPreferred(^uint64(0)), "score 40 must keep the preference")
}

// TestRemoteDAQualityScoreRace overlaps, on EACH of two sessions of one quota key, 8 competing-commit events (handleTx)
// with the production preference read of that same peer (daPrefetchPeers -> preferredDAPrefetchPeerKeyLocked ->
// qualityPreferred under stateMu); rivals[1] is torn down only after both lanes finish. At height 1440 =
// qualityGraceHeight normalization is a no-op, so the score ends at exactly 34 = 50 - 8 x 2.
func TestRemoteDAQualityScoreRace(t *testing.T) {
	h := highTipHarness(t, 1440)
	h.service.cfg.EnableCompactReceive = true
	f := newDAIngressFixture(t, h)
	daID := daRelayTestID(0xa0)
	must(t, daRelayTestPeer(h, "127.0.0.3:19113").handleTx(f.commit(daID, 2)), "first-seen commit")
	competitor := f.commit(daID, 2)
	rivals := []*peer{addDAPrefetchTestPeer(h.service, "127.0.0.1:19111", nil), addDAPrefetchTestPeer(h.service, "127.0.0.1:19112", nil)}
	var wg sync.WaitGroup
	failures := make(chan error, len(rivals)*8) // asserted on the test goroutine: FailNow is not for workers
	var writersDone atomic.Int32
	for _, rival := range rivals {
		wg.Add(2)
		go func(rival *peer) {
			defer func() { writersDone.Add(1); wg.Done() }()
			for i := 0; i < 8; i++ {
				if err := rival.handleTx(competitor); err != nil {
					failures <- err
				}
			}
		}(rival)
		go func(rival *peer) {
			defer wg.Done()
			for writersDone.Load() < int32(len(rivals)) {
				h.service.daPrefetchPeers(rival.addr())
			}
		}(rival)
	}
	wg.Wait()
	h.service.unregisterPeer(rivals[1])
	close(failures)
	for err := range failures {
		must(t, err, "competing commit")
	}
	for i, rival := range rivals {
		score, anchor := peerQuality(rival)
		state := rival.snapshotState()
		require(t, score == 34 && anchor == 1440 && state.BanScore == 0 && state.LastError == "", "rival %d: score=%d anchor=%d state=%+v, want 34 at 1440 with no ban", i, score, anchor, state)
	}
}

// p2pFunction parses one production source of this package and returns the named FuncDecl.
func p2pFunction(t *testing.T, path, name string) *ast.FuncDecl {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	must(t, err, "parse "+path)
	for _, decl := range file.Decls {
		if function, ok := decl.(*ast.FuncDecl); ok && function.Name.Name == name {
			return function
		}
	}
	t.Fatalf("%s: %s is not declared", path, name)
	return nil
}

func calleeOf(call *ast.CallExpr) string {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	}
	return ""
}

// TestRemoteDACleanupCallerEffects: the accepted-block and AnnounceBlock TTL ticks (a subtest)
// and, as source, AnnounceBlock's error precedence: broadcast error first, `return ttlErr` last.
func TestRemoteDACleanupCallerEffects(t *testing.T) {
	t.Run("ticks", TestAnnounceBlockAdvancesDARelayTTL)
	announce := p2pFunction(t, "service.go", "AnnounceBlock")
	var order []string
	ast.Inspect(announce.Body, func(node ast.Node) bool {
		if stmt, ok := node.(*ast.IfStmt); ok {
			if cond, ok := stmt.Cond.(*ast.BinaryExpr); ok {
				if name, ok := cond.X.(*ast.Ident); ok && (name.Name == "broadcastErr" || name.Name == "ttlErr") {
					order = append(order, name.Name)
				}
			}
		}
		return true
	})
	final, ok := announce.Body.List[len(announce.Body.List)-1].(*ast.ReturnStmt)
	require(t, slices.Equal(order, []string{"broadcastErr"}) && ok && len(final.Results) == 1 && types.ExprString(final.Results[0]) == "ttlErr", "AnnounceBlock error checks=%v last statement %T; want the broadcast error checked first and `return ttlErr` last", order, announce.Body.List[len(announce.Body.List)-1])
}

// TestRemoteDAResultDomainClosure: the structural half of UNREACHABLE_RESULT (two guarded effect
// arms, bare nil after a plain release, identity before latch before key, no candidate validation
// or standard authority on the DA arm, DA before the standard arm, no retired writer, handleConn's literal).
func TestRemoteDAResultDomainClosure(t *testing.T) {
	handler := p2pFunction(t, "da_relay_ingest.go", "handleRelayDATx")
	unlockAt, switchAt, identityAt, terminalAt := -1, -1, -1, -1
	for i, stmt := range handler.Body.List {
		ast.Inspect(stmt, func(node ast.Node) bool {
			switch call, ok := node.(*ast.CallExpr); {
			case ok && calleeOf(call) == "remoteDAProvenance":
				identityAt = i
			case ok && calleeOf(call) == "TerminalFaulted":
				terminalAt = i
			}
			return true
		})
		switch typed := stmt.(type) {
		case *ast.ExprStmt:
			if call, ok := typed.X.(*ast.CallExpr); ok && calleeOf(call) == "unlock" {
				unlockAt = i
			}
		case *ast.SwitchStmt:
			switchAt = i
			require(t, len(typed.Body.List) == 2, "result switch has %d cases, want exactly RETAINED and DUPLICATE-conflict", len(typed.Body.List))
			for _, clause := range typed.Body.List { // exact guard text, either order; a missing arm is a runtime row's failure
				require(t, len(clause.(*ast.CaseClause).List) == 1, "result case lists %d expressions, want exactly one guard", len(clause.(*ast.CaseClause).List))
				guard, effects := types.ExprString(clause.(*ast.CaseClause).List[0]), map[string]bool{}
				ast.Inspect(clause, func(node ast.Node) bool {
					if call, ok := node.(*ast.CallExpr); ok {
						effects[calleeOf(call)] = true
					}
					return true
				})
				retainedArm := guard == "result.Disposition == node.DAAdmissionRetained && !result.SameDAIDCommitConflict" && effects["scheduleDAPrefetch"] && len(effects) == 1
				conflictArm := guard == "result.Disposition == node.DAAdmissionDuplicate && result.SameDAIDCommitConflict" && effects["applyCompetingCommitScore"] && effects["LocalTipHeight"] && len(effects) == 2
				require(t, retainedArm || conflictArm, "result case %q carries effects %v", guard, effects)
			}
		case *ast.DeferStmt:
			t.Fatal("handleRelayDATx defers a release; the quota key must be released by a plain call before any result effect")
		}
	}
	last, ok := handler.Body.List[len(handler.Body.List)-1].(*ast.ReturnStmt)
	require(t, unlockAt >= 0 && switchAt > unlockAt && ok && len(last.Results) == 1 && types.ExprString(last.Results[0]) == "nil" && switchAt == len(handler.Body.List)-2, "unlock at %d, switch at %d of %d statements; the switch must follow the release and be followed only by `return nil`", unlockAt, switchAt, len(handler.Body.List))
	require(t, identityAt >= 0 && terminalAt > identityAt && unlockAt > terminalAt, "identity at %d, terminal latch at %d, unlock at %d; IDENTITY_REFUSAL precedes ALREADY_TERMINAL precedes the quota key", identityAt, terminalAt, unlockAt)
	forbidden := []string{"validateRelayDATxForAdmission", "ValidateDARelayChunk", "peerAddressKey", "normalizeNetAddr", "normalizeReconnectAddr", "ensureRelayTxAdmitted", "broadcastInventory", "Has", "Add", "Put", "UpsertPeer", "setLastError"}
	for _, name := range []string{"handleRelayDATx", "remoteDAProvenance", "penalizeDAAdmissionError", "applyCompetingCommitScore", "qualityPreferred", "normalizeQualityLocked"} {
		ast.Inspect(p2pFunction(t, "da_relay_ingest.go", name).Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				require(t, !slices.Contains(forbidden, calleeOf(call)), "%s calls %s", name, calleeOf(call))
			}
			return true
		})
	}
	dispatchAt, standardAt, hasAt, addAt := -1, -1, -1, -1
	for i, stmt := range p2pFunction(t, "handlers_tx.go", "handleTx").Body.List {
		ast.Inspect(stmt, func(node ast.Node) bool {
			ident, ok := node.(*ast.Ident)
			switch {
			case ok && ident.Name == "handleRelayDATx":
				dispatchAt = i
			case ok && ident.Name == "handleStandardTx":
				standardAt = i
			case ok && ident.Name == "txSeen":
				t.Fatalf("handleTx names txSeen at statement %d; the seen-set belongs to handleStandardTx", i)
			}
			return true
		})
	}
	require(t, dispatchAt >= 0 && standardAt > dispatchAt, "handleTx dispatches DA at statement %d and the standard arm at %d; the dispatch must come first", dispatchAt, standardAt)
	for i, stmt := range p2pFunction(t, "handlers_tx.go", "handleStandardTx").Body.List {
		ast.Inspect(stmt, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && calleeOf(call) == "Has" && hasAt < 0 {
				hasAt = i
			} else if ok && calleeOf(call) == "Add" && addAt < 0 {
				addAt = i
			}
			return true
		})
	}
	require(t, hasAt >= 0 && addAt > hasAt, "handleStandardTx reads txSeen.Has at %d and Add at %d; Has must come first", hasAt, addAt)
	entries, err := os.ReadDir(".")
	must(t, err, "ReadDir")
	legacy := []string{"StageCommit", "StageChunk", "stageRelayDATx", "stageRelayDACommitTx", "stageRelayDAChunkTx", "finishDAPrefetch", "scheduleDAPrefetchSnapshot", "daRelayCommitPayloadCommitment", "handleSeenRelayTxVariant", "validateAndMarkRelayTxSeen"}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		source, err := os.ReadFile(entry.Name())
		must(t, err, "read "+entry.Name())
		for _, name := range legacy {
			require(t, !bytes.Contains(source, []byte(name)), "%s still names the retired writer %s", entry.Name(), name)
		}
	}
	initialized := false
	ast.Inspect(p2pFunction(t, "service_peer_lifecycle.go", "handleConn").Body, func(node ast.Node) bool {
		if kv, ok := node.(*ast.KeyValueExpr); ok && types.ExprString(kv.Key) == "qualityScore" && types.ExprString(kv.Value) == "qualityScoreInitial" {
			initialized = true
		}
		return true
	})
	require(t, initialized, "handleConn's peer literal does not initialize qualityScore from the initial literal")
}
