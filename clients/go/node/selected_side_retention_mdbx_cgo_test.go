//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Literal retention results, spelled independently of the production constants.
const (
	retainStored    = "STORED_NONCANONICAL"
	retainDuplicate = "KNOWN_BLOCK_NOOP(STORED_NONCANONICAL)"
	retainKnown     = "KNOWN_BLOCK_NOOP(CANONICAL)"
	retainBusy      = "LOCAL_BUSY"
	retainStale     = "STALE_LOCAL_PLAN"
	retainInvariant = "TERMINAL_LOCAL_INVARIANT(evidence)"
	retainCleared   = "LOCAL_STORE_ERROR(noncanonical)"
	retainStorageIO = "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"
	retainCapacity  = "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"
	retainPrecommit = "LOCAL_PERSISTENCE_ERROR(precommit)"
	retainNA        = "NOT_APPLICABLE"
)

// newRetainStore is an exact-empty bootstrapped PRE_GENESIS store (PRUNED, active 1, next 2) tracked as an ssqWorld.
func newRetainStore(t *testing.T, spec ssqSpec) *ssqWorld {
	t.Helper()
	if spec.work == nil {
		spec.work = func(k uint64) [40]byte { return ssqWork(k + 1) }
	}
	w := &ssqWorld{
		t: t, path: filepath.Join(t.TempDir(), "db"), spec: spec, canonical: map[uint64][32]byte{}, side: map[uint64][32]byte{},
		headers: map[[32]byte][]byte{}, rows: map[string]ssqRow{},
	}
	var err error
	if w.store, err = mdbx.Create(w.path, ssqConfig); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = w.store.Close() })
	if w.owner, err = mdbx.NewOperationReservationOwner(mdbx.MaxOperationDataBytes); err != nil {
		t.Fatalf("reservation owner: %v", err)
	}
	if truth, _, err := w.store.BootstrapStorageV1(mdbx.StorageProfilePrunedV1, w.owner); err != nil || truth != mdbx.CommitTruthNew {
		t.Fatalf("bootstrap: %v/%v", truth, err)
	}
	genesis := DevnetGenesisBlockBytes()
	w.headers[DevnetGenesisBlockHash()] = genesis[:consensus.BLOCK_HEADER_BYTES]
	return w
}

// newRetainWorld commits the real published devnet genesis through its existing MDBX owner (header, body, paired
// index, undo, UTXO and counter), extends generation 1 with mined canonical blocks 1..tip (header, body and paired
// forward/owner rows) and writes the spec authority; every committed row is tracked for exact image proofs.
func newRetainWorld(t *testing.T, spec ssqSpec) *ssqWorld {
	t.Helper()
	w := newRetainStore(t, spec)
	genesis, hash := DevnetGenesisBlockBytes(), DevnetGenesisBlockHash()
	if out := consensus.ConnectPublishedGenesisMDBX(w.store, w.owner, genesis, genesis, DevnetGenesisChainID(), hash); out.Err != nil || out.Truth != mdbx.CommitTruthNew {
		t.Fatalf("published genesis: %+v", out)
	}
	_, txid, _, _, err := consensus.ParseTx(genesis[consensus.BLOCK_HEADER_BYTES+1:])
	if err != nil {
		t.Fatalf("genesis coinbase: %v", err)
	}
	w.canonical[0] = hash
	w.literal(3, bytes.Clone(hash[:]), genesis[:consensus.BLOCK_HEADER_BYTES], false)
	w.literal(4, bytes.Clone(hash[:]), genesis, false)
	w.literal(2, ssqMust(mdbx.HeightKey(1, 0)), mdbx.ChainValue(hash, [32]byte(genesis[4:36]), ssqWork(1)), false)
	w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, hash)), mdbx.CanonicalOwnerValue(0), false)
	w.literal(5, mdbx.UndoManifestKey(hash), mdbx.UndoManifestValue(0, [16]byte{}, 1, 0), false)
	w.preserve(1, ssqMust(mdbx.UTXOKey(1, txid, 0)))
	w.preserve(0, ssqMust(mdbx.MetaKey(0x10, 1)))
	// One whole header/body/forward/owner group per block, so apply's bounded batches keep each pair together; the
	// authority is the last group and is written once, in the final batch.
	var groups [][]mdbx.Mutation
	for k := uint64(1); k <= w.spec.tip; k++ {
		prev := w.canonical[k-1]
		block := w.mined(prev, 120)
		h := ssqHash(block)
		w.canonical[k] = h
		groups = append(groups, []mdbx.Mutation{
			w.literal(3, bytes.Clone(h[:]), block[:consensus.BLOCK_HEADER_BYTES], false), w.literal(4, bytes.Clone(h[:]), block, false),
			w.literal(2, ssqMust(mdbx.HeightKey(1, k)), mdbx.ChainValue(h, prev, w.spec.work(k)), false),
			w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, h)), mdbx.CanonicalOwnerValue(k), false),
		})
	}
	w.apply(append(groups, []mdbx.Mutation{w.authorityMutation(w.authorityValue())})...)
	return w
}

// preserve tracks one committed row this operation never owns at its current bytes, as the unchanged pre-state.
func (w *ssqWorld) preserve(rank uint8, key []byte) {
	w.t.Helper()
	var value []byte
	var present bool
	err := w.store.View(func(r *mdbx.Reader) error {
		var err error
		value, present, err = r.Get(ssqDBIs[rank], key)
		return err
	})
	if err != nil || !present {
		w.t.Fatalf("preserve %d/%x: present=%v %v", rank, key, present, err)
	}
	w.rows[string(append([]byte{rank}, key...))] = ssqRow{rank: rank, key: key, value: value}
}

func (w *ssqWorld) ts(hash [32]byte) uint64 {
	return binary.LittleEndian.Uint64(w.headers[hash][68:76])
}

// mined is one coinbase child of prev, gap seconds after it, under the inherited all-FF target.
func (w *ssqWorld) mined(prev [32]byte, gap uint64) []byte {
	w.t.Helper()
	block := ssqMine(w.t, prev, w.ts(prev)+gap, consensus.POW_LIMIT, nil)
	w.headers[ssqHash(block)] = block[:consensus.BLOCK_HEADER_BYTES]
	return block
}

func (w *ssqWorld) tipAt(k uint64) *mdbx.AuthorityPointV1 {
	return &mdbx.AuthorityPointV1{Height: k, BlockHash: w.canonical[k]}
}

func retainHeavy(tip uint64) func(uint64) [40]byte {
	return func(k uint64) [40]byte {
		if k == tip {
			return ssqWork(1 << 40)
		}
		return ssqWork(k + 1)
	}
}

// retainSide mines a side branch F+1..tip from canonical F and commits side g=2 over its last rows: each retained row
// is header, body and SideLink with cumulative work work-(tip-j); with history an earlier mined row keeps only its
// unowned header. The descriptor carries tip, work and the row count.
func (w *ssqWorld) retainSide(f, tip uint64, rows uint16, work uint64, history bool) map[uint64][]byte {
	w.t.Helper()
	blocks, prev, first := map[uint64][]byte{}, w.canonical[f], tip-uint64(rows)+1
	var muts []mdbx.Mutation
	for j := f + 1; j <= tip; j++ {
		block := w.mined(prev, 113)
		hash := ssqHash(block)
		blocks[j], w.side[j] = block, hash
		switch {
		case j >= first:
			muts = append(muts, w.literal(3, bytes.Clone(hash[:]), block[:consensus.BLOCK_HEADER_BYTES], false), w.literal(4, bytes.Clone(hash[:]), block, false),
				w.literal(6, ssqMust(mdbx.HeightKey(2, j)), mdbx.ChainValue(hash, prev, ssqWork(work-(tip-j))), false))
		case history:
			muts = append(muts, w.literal(3, bytes.Clone(hash[:]), block[:consensus.BLOCK_HEADER_BYTES], false))
		}
		prev = hash
	}
	a := w.authorityValue()
	a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 2, F: f, TipHeight: tip, TipHash: prev, CumulativeChainwork: ssqWork(work), RowCount: rows, LogicalBytes: uint64(rows) * 1_000}
	w.apply(append(muts, w.authorityMutation(a)))
	return blocks
}

// setSide rewrites only the committed selected descriptor.
func (w *ssqWorld) setSide(edit func(*mdbx.SelectedSideV1)) {
	w.t.Helper()
	a, err := mdbx.DecodeStorageAuthorityV1(w.rows[string([]byte{0, 2})].value)
	if err != nil {
		w.t.Fatalf("authority decode: %v", err)
	}
	edit(a.SelectedSide)
	w.apply([]mdbx.Mutation{w.authorityMutation(a)})
}

// canonicalChild mines a valid child of canonical 5 and commits it as canonical 6 (header, paired index and, when body,
// its body) under a mined canonical 7, so the candidate is a canonical block below the tip.
func (w *ssqWorld) canonicalChild(body bool) []byte {
	w.t.Helper()
	raw := w.child(w.canonical[5], 6, nil)
	hash := ssqHash(raw)
	w.absent = slices.DeleteFunc(w.absent, func(h [32]byte) bool { return h == hash })
	w.headers[hash] = raw[:consensus.BLOCK_HEADER_BYTES]
	next := w.mined(hash, 120)
	nextHash := ssqHash(next)
	w.canonical[6], w.canonical[7] = hash, nextHash
	rows := []mdbx.Mutation{
		w.literal(3, bytes.Clone(hash[:]), raw[:consensus.BLOCK_HEADER_BYTES], false),
		w.literal(2, ssqMust(mdbx.HeightKey(1, 6)), mdbx.ChainValue(hash, w.canonical[5], ssqWork(7)), false),
		w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, hash)), mdbx.CanonicalOwnerValue(6), false),
		w.literal(3, bytes.Clone(nextHash[:]), next[:consensus.BLOCK_HEADER_BYTES], false),
		w.literal(4, bytes.Clone(nextHash[:]), next, false),
		w.literal(2, ssqMust(mdbx.HeightKey(1, 7)), mdbx.ChainValue(nextHash, hash, ssqWork(8)), false),
		w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, nextHash)), mdbx.CanonicalOwnerValue(7), false),
	}
	if body {
		rows = append(rows, w.literal(4, bytes.Clone(hash[:]), raw, false))
	}
	w.apply(rows)
	return raw
}

// retainMerkle flips one byte of the coinbase output value: the header and hash are unchanged and step 5 fails.
func retainMerkle(raw []byte) []byte {
	out := bytes.Clone(raw)
	// The CompactSize tx count is one byte, or 0xfd plus two bytes for retainLarge's 253..65535 transactions; then
	// version 4, kind 1, nonce 8, input count 1, one input 41 and output count 1 precede the value.
	coinbase := consensus.BLOCK_HEADER_BYTES + 1
	if raw[consensus.BLOCK_HEADER_BYTES] == 0xfd {
		coinbase += 2
	}
	out[coinbase+56] ^= 1
	return out
}

// retainWitness gives the single coinbase one canonical empty sentinel witness item. Steps 1-12 commit the coinbase
// wtxid as zero and its txid excludes the witness, so the header, Merkle root and witness commitment stay valid while
// the body bytes differ.
func retainWitness(raw []byte) []byte {
	return append(bytes.Clone(raw[:len(raw)-2]), 1, consensus.SUITE_ID_SENTINEL, 0, 0, 0)
}

// retainCoinbase is the one-output coinbase of ssqTx(true) committing to commitment.
func retainCoinbase(commitment [32]byte) []byte {
	b := consensus.AppendU64le(append(consensus.AppendU32le(nil, 1), 0x00), 0)
	b = consensus.AppendU32le(append(consensus.AppendCompactSize(b, 1), make([]byte, 32)...), math.MaxUint32)
	b = consensus.AppendU32le(consensus.AppendCompactSize(b, 0), math.MaxUint32)
	b = consensus.AppendU16le(consensus.AppendU64le(consensus.AppendCompactSize(b, 1), 0), consensus.COV_TYPE_ANCHOR)
	b = append(consensus.AppendCompactSize(b, 32), commitment[:]...)
	return consensus.AppendCompactSize(consensus.AppendCompactSize(consensus.AppendU32le(b, 0), 0), 0)
}

// retainLarge builds a steps-1-12-valid block of exactly n bytes over parent: after the 116-byte header, the 3-byte
// count and the 105-byte coinbase, the rest is split over input-free transactions of 65565..100020 bytes, each one
// unknown-suite witness item (pubkey 65536..99991 bytes, one-byte signature), so every witness stays within
// MAX_WITNESS_BYTES_PER_TX and each transaction weighs its size plus 121.
func retainLarge(t *testing.T, parent [32]byte, timestamp uint64, n int) []byte {
	t.Helper()
	rem := n - consensus.BLOCK_HEADER_BYTES - 3 - 105
	count := (rem + 100_019) / 100_020
	txs, txids, wtxids := make([][]byte, 0, count), make([][32]byte, 1, count+1), make([][32]byte, 1, count+1)
	for i := 0; i < count; i++ {
		size := rem / count
		if i < rem%count {
			size++
		}
		tx := consensus.AppendU64le(append(consensus.AppendU32le(nil, 1), 0x00), uint64(i)+1) //nolint:gosec // i < count.
		tx = append(consensus.AppendU32le(append(tx, 0, 0), 0), 1, 0x7f)
		tx = consensus.AppendCompactSize(tx, uint64(size-29)) //nolint:gosec // size >= 65565.
		tx = append(append(tx, make([]byte, size-29)...), 1, 1, 0)
		_, txid, wtxid, used, err := consensus.ParseTx(tx)
		if err != nil || used != size || size < 65_565 || size > 100_020 {
			t.Fatalf("large tx %d: size %d used %d (%v)", i, size, used, err)
		}
		txs, txids, wtxids = append(txs, tx), append(txids, txid), append(wtxids, wtxid)
	}
	witnessRoot, err := consensus.WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("witness root: %v", err)
	}
	coinbase := retainCoinbase(consensus.WitnessCommitmentHash(witnessRoot))
	if _, txids[0], _, _, err = consensus.ParseTx(coinbase); err != nil {
		t.Fatalf("coinbase: %v", err)
	}
	root, err := consensus.MerkleRootTxids(txids)
	if err != nil {
		t.Fatalf("merkle root: %v", err)
	}
	block := append(make([]byte, 0, n), ssqHeader(parent, root, timestamp, consensus.POW_LIMIT, 0)...)
	block = append(consensus.AppendCompactSize(block, uint64(count+1)), coinbase...) //nolint:gosec // count+1 > 252.
	for _, tx := range txs {
		block = append(block, tx...)
	}
	if len(block) != n {
		t.Fatalf("large block is %d bytes, want %d", len(block), n)
	}
	return block
}

// retain invokes the real entrypoint once and proves the caller's raw bytes and locator unchanged and the lane released.
func (w *ssqWorld) retain(raw []byte, tip *mdbx.AuthorityPointV1) SelectedSideMutationOutcome {
	w.t.Helper()
	return w.operate(RetainSelectedSideMDBX, raw, tip)
}

// replaceSide invokes the separate N3 entrypoint with retain's input and lane proofs.
func (w *ssqWorld) replaceSide(raw []byte, tip *mdbx.AuthorityPointV1) SelectedSideMutationOutcome {
	w.t.Helper()
	return w.operate(ReplaceSelectedSideMDBX, raw, tip)
}

func (w *ssqWorld) operate(op func(*mdbx.Store, *mdbx.OperationReservationOwner, []byte, *mdbx.AuthorityPointV1) SelectedSideMutationOutcome, raw []byte, tip *mdbx.AuthorityPointV1) SelectedSideMutationOutcome {
	w.t.Helper()
	before := bytes.Clone(raw)
	var locator mdbx.AuthorityPointV1
	if tip != nil {
		locator = *tip
	}
	out := op(w.store, w.owner, raw, tip)
	w.wantRaw(raw, before)
	if tip != nil && *tip != locator {
		w.t.Fatal("retention changed the caller's tip locator")
	}
	retainWantReleased(w.t, w.owner)
	return out
}

// expectN1 records the literal N1 effect from the pre-state authority: side(g,F,F+1,hash,work,1,n), next g+1 and the
// inserted header, body and SideLink(g,F+1).
func (w *ssqWorld) expectN1(raw []byte, a mdbx.StorageAuthorityV1, g, f uint64, work [40]byte) {
	w.t.Helper()
	hash := ssqHash(raw)
	w.absent = slices.DeleteFunc(w.absent, func(h [32]byte) bool { return h == hash })
	a.NextGenerationID = g + 1
	a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: g, F: f, TipHeight: f + 1, TipHash: hash, CumulativeChainwork: work, RowCount: 1, LogicalBytes: uint64(len(raw))}
	w.authorityMutation(a)
	w.literal(3, bytes.Clone(hash[:]), raw[:consensus.BLOCK_HEADER_BYTES], false)
	w.literal(4, bytes.Clone(hash[:]), bytes.Clone(raw), false)
	w.literal(6, ssqMust(mdbx.HeightKey(g, f+1)), mdbx.ChainValue(hash, w.canonical[f], work), false)
}

// expectN2 records the literal N2 effect over the tracked pre-state authority a: the caller's literal side (g, F and
// next unchanged) and the inserted candidate header, body and SideLink(g, side tip) naming parent.
func (w *ssqWorld) expectN2(raw []byte, a mdbx.StorageAuthorityV1, side mdbx.SelectedSideV1, parent [32]byte) {
	w.t.Helper()
	hash := ssqHash(raw)
	w.absent = slices.DeleteFunc(w.absent, func(h [32]byte) bool { return h == hash })
	a.SelectedSide = &side
	w.authorityMutation(a)
	w.literal(3, bytes.Clone(hash[:]), raw[:consensus.BLOCK_HEADER_BYTES], false)
	w.literal(4, bytes.Clone(hash[:]), bytes.Clone(raw), false)
	w.literal(6, ssqMust(mdbx.HeightKey(side.GenerationID, side.TipHeight)), mdbx.ChainValue(hash, parent, side.CumulativeChainwork), false)
}

// tracked decodes the tracked (committed) authority row, the independent pre-state snapshot of an effect.
func (w *ssqWorld) tracked() mdbx.StorageAuthorityV1 {
	w.t.Helper()
	a, err := mdbx.DecodeStorageAuthorityV1(w.rows[string([]byte{0, 2})].value)
	if err != nil {
		w.t.Fatalf("authority decode: %v", err)
	}
	return a
}

// persisted decodes the authority actually committed in the Store.
func (w *ssqWorld) persisted() mdbx.StorageAuthorityV1 {
	w.t.Helper()
	var a mdbx.StorageAuthorityV1
	err := w.store.View(func(r *mdbx.Reader) error {
		value, _, err := r.Get(ssqDBIs[0], []byte{2})
		if err == nil {
			a, err = mdbx.DecodeStorageAuthorityV1(value)
		}
		return err
	})
	if err != nil {
		w.t.Fatalf("persisted authority: %v", err)
	}
	return a
}

// wantN1Image proves the tracked image and that the candidate's compact undo manifest stayed absent.
func (w *ssqWorld) wantN1Image(label string, raw []byte) {
	w.t.Helper()
	w.wantImage(label)
	w.wantAbsent(label, 5, mdbx.UndoManifestKey(ssqHash(raw)))
}

func (w *ssqWorld) wantAbsent(label string, rank uint8, key []byte) {
	w.t.Helper()
	check := w.rawEqual
	if check == nil {
		check = w.viewEqual
	}
	if equal, err := check(rank, key, nil); err != nil || !equal {
		w.t.Fatalf("%s: row %d/%x present (%v)", label, rank, key, err)
	}
}

// wantCleared proves the literal complete clear of side(2,first..tip), healthy (N3) or positive-damage, from the pre-side
// authority: no selected side, PRUNE_GC and SIDE(2,first,tip,first); every leaving header except kept is absent, bodies
// and links stay.
func (w *ssqWorld) wantCleared(label string, first, tip uint64, kept ...uint64) {
	w.t.Helper()
	a := w.authorityValue()
	a.Phase = mdbx.StoragePhasePruneGCV1
	a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 2, FirstHeight: first, LastHeight: tip, NextHeight: first}}}
	w.authorityMutation(a)
	var gone [][]byte
	for j := first; j <= tip; j++ {
		if hash := w.side[j]; !slices.Contains(kept, j) {
			gone = append(gone, w.absentRow(3, bytes.Clone(hash[:])).Key)
		}
	}
	w.wantImage(label)
	for _, key := range gone {
		w.wantAbsent(label, 3, key)
	}
}

// retainWantReleased proves the full lane is free: one full grant succeeds and a nested one-byte grant inside it is refused.
func retainWantReleased(t *testing.T, owner *mdbx.OperationReservationOwner) {
	t.Helper()
	err := owner.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		if owner.WithReservation(1, func() error { return nil }) == nil {
			return errors.New("full lane admitted a nested grant")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("full lane still charged: %v", err)
	}
}

func retainWant(t *testing.T, label string, out SelectedSideMutationOutcome, result, decision, canonical string, truth mdbx.CommitTruth, stage mdbx.UpdateStage, clean bool) {
	t.Helper()
	if out.Result != result || out.Decision != decision || out.CanonicalTruth != canonical || out.Truth != truth || out.Stage != stage || (out.Err == nil) != clean {
		t.Fatalf("%s: outcome %+v", label, out)
	}
}

// retainWantRefusal requires a typed OLD/Prewrite refusal of exactly result whose own cause is cause ("" skips it).
func retainWantRefusal(t *testing.T, label string, out SelectedSideMutationOutcome, result, cause string) {
	t.Helper()
	retainWant(t, label, out, result, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, false)
	var failure *selectedSideQualificationError
	if !errors.As(out.Err, &failure) || failure.Result != result || cause != "" && failure.Cause.Error() != cause {
		t.Fatalf("%s: typed refusal lost: %v", label, out.Err)
	}
}

// retainWantIntegrity requires the Reader's recorded get/Integrity failure, classified canonical integrity.
func retainWantIntegrity(t *testing.T, label string, out SelectedSideMutationOutcome, diagnostic string) {
	t.Helper()
	retainWant(t, label, out, ssqIntegrity, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, false)
	var engine *mdbx.EngineError
	if !errors.As(out.Err, &engine) || engine.Class != mdbx.EngineIntegrity || engine.Operation != "get" || diagnostic != "" && engine.Diagnostic != diagnostic {
		t.Fatalf("%s: recorded integrity lost: %v", label, out.Err)
	}
}

func retainWantConsensus(t *testing.T, label string, out SelectedSideMutationOutcome, code consensus.ErrorCode) {
	t.Helper()
	retainWant(t, label, out, "CONSENSUS_INVALID("+string(code)+")", "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, false)
	tx, ok := out.Err.(*consensus.TxError) //nolint:errorlint // The exact direct consensus error.
	if !ok || tx.Code != code {
		t.Fatalf("%s: consensus error %v", label, out.Err)
	}
}

func retainWantEngine(t *testing.T, label string, err error, operation string, class mdbx.EngineClass, code int, diagnostic string) {
	t.Helper()
	engine, ok := err.(*mdbx.EngineError) //nolint:errorlint // The exact direct unclassified API error.
	if !ok || engine.Operation != operation || engine.Class != class || engine.Code != code || engine.Diagnostic != diagnostic {
		t.Fatalf("%s: error %v", label, err)
	}
}

func TestSelectedSideRetention(t *testing.T) {
	old, pre := mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite
	newT, crossed := mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed
	nextTwo := func(a *mdbx.StorageAuthorityV1) { a.NextGenerationID = 2 }
	exhausted := func(a *mdbx.StorageAuthorityV1) { a.NextGenerationID = math.MaxUint64 }
	prune := func(a *mdbx.StorageAuthorityV1) {
		a.B, a.U, a.Phase = 5, 13_685, mdbx.StoragePhasePruneGCV1
		a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanBlocksV1, GenerationID: 1, FirstHeight: 0, LastHeight: 4, NextHeight: 2}}}
	}
	detached := func(a *mdbx.StorageAuthorityV1) {
		prune(a)
		entries := make([]mdbx.DetachedSuffixEntryV1, 1_440)
		for i := range entries {
			entries[i] = mdbx.DetachedSuffixEntryV1{Height: 2_000 - uint64(i), Hash: [32]byte{0xde, byte(i >> 8), byte(i)}, BlockBytesLen: 100}
		}
		a.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: entries, Cursor: mdbx.AuthorityPointV1{Height: 2_000, BlockHash: entries[0].Hash}, EntryCount: 1_440, LogicalBytes: 144_000}
	}
	sideWait := func(next uint64) func(*mdbx.StorageAuthorityV1) {
		return func(a *mdbx.StorageAuthorityV1) {
			a.NextGenerationID, a.Phase = next, mdbx.StoragePhasePruneGCV1
			a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 5, FirstHeight: 11, LastHeight: 15, NextHeight: 11}}}
		}
	}
	both := func(edits ...func(*mdbx.StorageAuthorityV1)) func(*mdbx.StorageAuthorityV1) {
		return func(a *mdbx.StorageAuthorityV1) {
			for _, edit := range edits {
				edit(a)
			}
		}
	}
	for _, c := range []struct {
		name string
		edit func(*mdbx.StorageAuthorityV1)
	}{{"A1", nextTwo}, {"A2", both(nextTwo, prune)}} {
		t.Run(c.name, func(t *testing.T) {
			w := newRetainWorld(t, ssqSpec{tip: 10, authority: c.edit})
			prior := w.authorityValue()
			raw := w.child(w.canonical[5], 6, nil)
			out := w.retain(raw, w.tipAt(10))
			retainWant(t, "clean STORED_NONCANONICAL/not-applicable", out, retainStored, "", retainNA, newT, crossed, true)
			// The persisted next generation is checked on its own before the whole image.
			var next uint64
			err := w.store.View(func(r *mdbx.Reader) error {
				value, _, err := r.Get(ssqDBIs[0], []byte{2})
				if err == nil {
					var a mdbx.StorageAuthorityV1
					a, err = mdbx.DecodeStorageAuthorityV1(value)
					next = a.NextGenerationID
				}
				return err
			})
			if err != nil || next != 3 {
				t.Fatalf("N1 exact authority/next: next %d (%v)", next, err)
			}
			w.expectN1(raw, prior, 2, 5, ssqWork(7))
			w.wantN1Image("N1 selected generation and exact image", raw)
			w.reopen()
			w.wantN1Image("N1 persisted image after reopen", raw)
		})
	}
	t.Run("A9-reopen", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10, authority: nextTwo})
		prior := w.authorityValue()
		raw := w.child(w.canonical[5], 6, nil)
		retainWant(t, "first N1", w.retain(raw, w.tipAt(10)), retainStored, "", retainNA, newT, crossed, true)
		w.expectN1(raw, prior, 2, 5, ssqWork(7))
		w.reopen()
		w.wantN1Image("byte-identical persisted image only", raw)
		out := w.retain(w.child(w.canonical[4], 5, nil), w.tipAt(10))
		retainWant(t, "unclassified exact get EINVAL/not verified/no effect", out, "", "", "OLD", old, pre, false)
		retainWantEngine(t, "unverified owner", out.Err, "get", mdbx.EngineInvalidInput, 22, "canonical owner index is not verified")
		w.wantImage("unverified owner refusal")
	})
	t.Run("inputs", func(t *testing.T) {
		out := RetainSelectedSideMDBX(nil, nil, nil, nil)
		retainWant(t, "nil Store", out, "", "", "", old, pre, false)
		retainWantEngine(t, "nil Store", out.Err, "update", mdbx.EngineInvalidInput, 22, "nil Store")
		// A nil Store keeps precedence over an invalid owner and an oversized candidate, which stays unchanged.
		for _, owner := range []*mdbx.OperationReservationOwner{nil, {}} {
			oversize := make([]byte, mdbx.MaxBlockBytes+1)
			oversize[0] = 0x5a
			before := bytes.Clone(oversize)
			out := RetainSelectedSideMDBX(nil, owner, oversize, nil)
			if !bytes.Equal(oversize, before) {
				t.Fatal("nil Store refusal changed the caller's raw bytes")
			}
			retainWant(t, "nil Store before invalid owner and raw bound", out, "", "", "", old, pre, false)
			retainWantEngine(t, "nil Store before invalid owner and raw bound", out.Err, "update", mdbx.EngineInvalidInput, 22, "nil Store")
		}
		w := newRetainWorld(t, ssqSpec{tip: 10})
		raw := w.child(w.canonical[5], 6, nil)
		before := bytes.Clone(raw)
		for _, owner := range []*mdbx.OperationReservationOwner{nil, {}} {
			tip := w.tipAt(10)
			out := RetainSelectedSideMDBX(w.store, owner, raw, tip)
			w.wantRaw(raw, before)
			if *tip != *w.tipAt(10) {
				t.Fatal("owner input changed the caller's tip locator")
			}
			retainWant(t, "owner input", out, "", "", "", old, pre, false)
			if out.Err.Error() != "invalid storage operation reservation input" {
				t.Fatalf("owner input error %v", out.Err)
			}
		}
		w.wantImage("owner input refusal")
	})
	t.Run("R-a", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10, authority: detached})
		out := w.retain(w.child(w.canonical[5], 6, nil), w.tipAt(10))
		retainWant(t, "descriptor LOCAL_BUSY precedes aggregate", out, retainBusy, "", "OLD", old, pre, true)
		w.wantImage("descriptor busy")
	})
	for _, c := range []struct {
		name string
		edit func(*mdbx.StorageAuthorityV1)
	}{{"R-b", sideWait(9)}, {"R-b-progress", both(sideWait(9), func(a *mdbx.StorageAuthorityV1) { a.Cleanup.Spans[0].NextHeight = 13 })}} {
		t.Run(c.name, func(t *testing.T) {
			w := newRetainWorld(t, ssqSpec{tip: 10, authority: c.edit})
			out := w.retain(w.child(w.canonical[5], 6, nil), w.tipAt(10))
			retainWantRefusal(t, "SIDE wait no allocation/exact branch_data", out, ssqBranch, "selected side creation waits for its SIDE cleanup")
			w.wantImage("SIDE unchanged")
		})
	}
	for _, c := range []struct {
		name, label, result string
		edit                func(*mdbx.StorageAuthorityV1)
	}{
		{"R-c1", "ordinary recovery_artifact and fixed cursor", ssqRecovery, ssqOrdinary},
		{"R-c2", "NONE RECOVERY_REQUIRED without artifacts", ssqRequired, ssqPendingNone},
		{"R-c3", "RECOVERY_REQUIRED/image", ssqRequired, ssqPrune(true)},
		{"R-c4", "RECOVERY_REQUIRED/image", ssqRequired, ssqReplay},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newRetainWorld(t, ssqSpec{tip: 10, authority: c.edit})
			retainWantRefusal(t, c.label, w.retain(w.child(w.canonical[5], 6, nil), w.tipAt(10)), c.result, "")
			w.wantImage(c.label)
		})
	}
	t.Run("R-d", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
		w.retainSide(0, 1_440, 1_440, 1_441, false)
		out := w.retain(w.child(w.side[1_440], 1_441, nil), w.tipAt(2))
		retainWant(t, "no early append/PREPARE_ROLLING", out, ssqBranch, "PREPARE_ROLLING", "OLD", old, pre, true)
		w.wantImage("full side unchanged")
		// The cleaned one-slot shape (F0, C1441 >= 1440, count 1439, history rows 1..2 header-only) is the later RA
		// append: its selected exact-tip child is refused as typed branch_data, never appended as N2.
		w = newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
		w.retainSide(0, 1_441, 1_439, 1_442, true)
		out = w.retain(w.child(w.side[1_441], 1_442, nil), w.tipAt(2))
		retainWantRefusal(t, "one-slot append stays a later transition", out, ssqBranch, "selected side append belongs to a later transition")
		w.wantImage("one-slot side unchanged")
	})
	// A3a is the contract case g5/F5/next7; A3a-exhausted keeps next=maxuint64, where N2 still allocates nothing.
	for _, c := range []struct {
		name string
		next uint64
	}{{"A3a", 7}, {"A3a-exhausted", math.MaxUint64}} {
		next := c.next
		t.Run(c.name, func(t *testing.T) {
			// count1, F5, g5, next: a mined side tip at 6 planted with g5 link keys; the exact-tip child (work 8) neither
			// wins K23 (canonical tip work 11) nor loses selection (side 7). No identity is allocated, even when exhausted.
			w := newRetainWorld(t, ssqSpec{tip: 10, authority: func(a *mdbx.StorageAuthorityV1) { a.NextGenerationID = next }})
			tip := w.mined(w.canonical[5], 113)
			hash := ssqHash(tip)
			a := w.authorityValue()
			a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 5, F: 5, TipHeight: 6, TipHash: hash, CumulativeChainwork: ssqWork(7), RowCount: 1, LogicalBytes: uint64(len(tip))}
			w.apply([]mdbx.Mutation{
				w.literal(3, bytes.Clone(hash[:]), tip[:consensus.BLOCK_HEADER_BYTES], false), w.literal(4, bytes.Clone(hash[:]), tip, false),
				w.literal(6, ssqMust(mdbx.HeightKey(5, 6)), mdbx.ChainValue(hash, w.canonical[5], ssqWork(7)), false), w.authorityMutation(a),
			})
			prior := w.tracked()
			raw := w.child(hash, 7, nil)
			retainWant(t, "clean N2 STORED_NONCANONICAL/not-applicable", w.retain(raw, w.tipAt(10)), retainStored, "", retainNA, newT, crossed, true)
			if got := w.persisted(); got.NextGenerationID != next || got.SelectedSide == nil || got.SelectedSide.GenerationID != 5 || got.SelectedSide.F != 5 {
				t.Fatalf("append generation/next preserved: %+v", got)
			}
			side := mdbx.SelectedSideV1{GenerationID: 5, F: 5, TipHeight: 7, TipHash: ssqHash(raw), CumulativeChainwork: ssqWork(8), RowCount: 2, LogicalBytes: uint64(len(tip) + len(raw))}
			w.expectN2(raw, prior, side, hash)
			w.wantN1Image("N2 exact append image", raw)
			w.reopen()
			w.wantN1Image("N2 persisted image after reopen", raw)
			out := w.retain(w.child(w.canonical[4], 5, nil), w.tipAt(10))
			retainWant(t, "unclassified exact get EINVAL/not verified/no effect", out, "", "", "OLD", old, pre, false)
			retainWantEngine(t, "unverified owner after N2", out.Err, "get", mdbx.EngineInvalidInput, 22, "canonical owner index is not verified")
			w.wantImage("unverified owner refusal after N2")
		})
	}
	t.Run("A3b", func(t *testing.T) {
		// F0/C1439/count1439 is the full form: its exact-tip child at 1440 appends to physical 1..1440, count 1440, with
		// NONE/STABLE and no SIDE. The planted logical bytes are the actual retained body total.
		w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
		blocks := w.retainSide(0, 1_439, 1_439, 1_440, false)
		var total uint64
		for j := uint64(1); j <= 1_439; j++ {
			total += uint64(len(blocks[j]))
		}
		w.setSide(func(s *mdbx.SelectedSideV1) { s.LogicalBytes = total })
		prior := w.tracked()
		raw := w.child(w.side[1_439], 1_440, nil)
		retainWant(t, "clean C1439 append", w.retain(raw, w.tipAt(2)), retainStored, "", retainNA, newT, crossed, true)
		side := mdbx.SelectedSideV1{GenerationID: 2, F: 0, TipHeight: 1_440, TipHash: ssqHash(raw), CumulativeChainwork: ssqWork(1_441), RowCount: 1_440, LogicalBytes: total + uint64(len(raw))}
		w.expectN2(raw, prior, side, w.side[1_439])
		w.wantN1Image("ordinary 1439 append image", raw)
		w.reopen()
		w.wantN1Image("ordinary 1439 append persisted image after reopen", raw)
		out := w.retain(w.child(w.canonical[1], 2, nil), w.tipAt(2))
		retainWant(t, "unclassified exact get EINVAL/not verified/no effect", out, "", "", "OLD", old, pre, false)
		retainWantEngine(t, "unverified owner after C1439 append", out.Err, "get", mdbx.EngineInvalidInput, 22, "canonical owner index is not verified")
		w.wantImage("unverified owner refusal after C1439 append")
	})
	t.Run("R-i", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		out := w.retain(w.child(w.canonical[10], 11, nil), w.tipAt(10))
		retainWant(t, "ORDINARY decision and zero side effect", out, "", "ORDINARY", "OLD", old, pre, true)
		w.wantImage("ordinary routing")
	})
	t.Run("R-tip-current", func(t *testing.T) {
		tie := func(k uint64) [40]byte {
			if k == 10 {
				return ssqWork(7)
			}
			return ssqWork(k + 1)
		}
		w := newRetainWorld(t, ssqSpec{tip: 10, work: tie, authority: nextTwo})
		c10 := w.canonical[10]
		smaller := w.child(w.canonical[5], 6, func(h [32]byte) bool { return bytes.Compare(h[:], c10[:]) < 0 })
		retainWant(t, "canonical work/tie route exact ORDINARY/no mutation", w.retain(smaller, w.tipAt(10)), "", "ORDINARY", "OLD", old, pre, true)
		w.wantImage("tie ORDINARY")
		prior := w.authorityValue()
		larger := w.child(w.canonical[5], 6, func(h [32]byte) bool { return bytes.Compare(h[:], c10[:]) > 0 })
		retainWant(t, "larger-hash tie keeps optional N1", w.retain(larger, w.tipAt(10)), retainStored, "", retainNA, newT, crossed, true)
		w.expectN1(larger, prior, 2, 5, ssqWork(7))
		w.wantN1Image("tie N1 from stored F<H entry", larger)
	})
	t.Run("R-tip-stale", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		raw := w.child(w.canonical[5], 6, nil)
		for _, c := range []struct {
			name string
			tip  *mdbx.AuthorityPointV1
		}{
			{"stale hash", &mdbx.AuthorityPointV1{Height: 10, BlockHash: w.canonical[9]}},
			{"absent height", &mdbx.AuthorityPointV1{Height: 11, BlockHash: w.canonical[10]}},
			{"nil with nonempty generation", nil},
		} {
			retainWantRefusal(t, c.name, w.retain(raw, c.tip), retainStale, "expected selected retention tip is not the current canonical tip")
			w.wantImage(c.name)
		}
	})
	t.Run("R-tip-stale-height", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		retainWantRefusal(t, "STALE_LOCAL_PLAN/no side write", w.retain(w.child(w.canonical[5], 6, nil), w.tipAt(9)), retainStale, "")
		w.wantImage("old height with nonempty suffix")
	})
	t.Run("R-tip-work", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		w.apply([]mdbx.Mutation{
			w.literal(2, ssqMust(mdbx.HeightKey(1, 10)), mdbx.ChainValue(w.canonical[10], w.canonical[9], [40]byte{}), true),
			w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, w.canonical[10])), mdbx.CanonicalOwnerValue(10), true),
		})
		stale := &mdbx.AuthorityPointV1{Height: 10, BlockHash: w.canonical[9]}
		out := w.retain(w.child(w.canonical[5], 6, nil), stale)
		retainWantRefusal(t, "canonical integrity precedes stale hash", out, ssqIntegrity, "expected selected retention tip work is outside its domain")
		w.wantImage("invalid tip work")
	})
	t.Run("R-tip-invalid", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		out := w.retain(w.child(w.canonical[5], 6, nil), &mdbx.AuthorityPointV1{Height: 1 << 32, BlockHash: w.canonical[10]})
		retainWant(t, "unclassified invalid tip", out, "", "", "OLD", old, pre, false)
		retainWantEngine(t, "invalid tip", out.Err, "update", mdbx.EngineInvalidInput, 22, "invalid selected retention tip")
		w.wantImage("invalid tip")
	})
	t.Run("R-domain-pregenesis", func(t *testing.T) {
		w := newRetainStore(t, ssqSpec{})
		w.preserve(0, []byte{2})
		genesis := DevnetGenesisBlockHash()
		raw := w.childAt(genesis, w.ts(genesis)+120, consensus.POW_LIMIT, nil)
		out := w.retain(raw, nil)
		retainWantRefusal(t, "PRE_GENESIS parent branch_data without a scan", out, ssqBranch, "candidate parent is neither an active canonical block nor the selected tip")
		w.wantImage("PRE_GENESIS unchanged")
	})
	t.Run("R-domain-h0", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 0})
		out := w.retain(w.child(w.canonical[0], 1, nil), w.tipAt(0))
		retainWant(t, "H0 child outranks genesis: ORDINARY, no F==H N1", out, "", "ORDINARY", "OLD", old, pre, true)
		w.wantImage("H0 unchanged")
	})
	t.Run("R-kc1", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 5, authority: exhausted})
		raw := w.canonicalChild(true)
		// The invalid locator also proves canonical-known precedes the expected-tip proof.
		out := w.retain(raw, &mdbx.AuthorityPointV1{Height: 1 << 32})
		retainWant(t, "canonical-known before exhausted allocation/no side effect", out, retainKnown, "", retainNA, old, pre, true)
		w.wantImage("canonical-known")
	})
	for _, b := range []uint64{0, 7} {
		t.Run(fmt.Sprintf("R-kc2-B%d", b), func(t *testing.T) {
			promise := func(a *mdbx.StorageAuthorityV1) {
				if b > 0 {
					a.B, a.U = b, b+13_680
				}
			}
			w := newRetainWorld(t, ssqSpec{tip: 5, authority: promise})
			w.retainSide(2, 4, 2, 5, false)
			raw := w.canonicalChild(b == 0)
			retainWant(t, "canonical-known with healthy side", w.retain(raw, w.tipAt(7)), retainKnown, "", retainNA, old, pre, true)
			w.wantImage("side and physical bytes preserved")
			if b > 0 {
				hash := ssqHash(raw)
				w.wantAbsent("pruned candidate body not reacquired", 4, bytes.Clone(hash[:]))
			}
		})
	}
	t.Run("R-kc3", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 5})
		raw := w.canonicalChild(true)
		out := w.retain(retainMerkle(raw), &mdbx.AuthorityPointV1{Height: 1 << 32})
		retainWantConsensus(t, "earlier exact merkle code before owner", out, consensus.BLOCK_ERR_MERKLE_INVALID)
		w.wantImage("invalid known candidate")
	})
	t.Run("R-q", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 20})
		w.retainSide(10, 15, 5, 16, false)
		out := w.retain(w.child(w.side[13], 14, nil), w.tipAt(20))
		retainWantRefusal(t, "not-appendable branch_data/no body14", out, ssqBranch, "candidate parent is neither an active canonical block nor the selected tip")
		w.wantImage("inside-interval parent")
	})
	t.Run("R-k-last", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(3, 8, 5, 9, false)
		for _, c := range []struct {
			h     uint64
			label string
		}{{8, "healthy physical last-row duplicate exact stored-known"}, {6, "healthy physical interior-row duplicate exact stored-known"}} {
			out := w.retain(blocks[c.h], w.tipAt(10))
			retainWant(t, c.label, out, retainDuplicate, "", retainNA, old, pre, true)
			w.wantImage(c.label)
		}
	})
	t.Run("R-k-invalid", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(3, 8, 5, 9, false)
		retainWantConsensus(t, "exact supplied merkle error/no clear", w.retain(retainMerkle(blocks[8]), w.tipAt(10)), consensus.BLOCK_ERR_MERKLE_INVALID)
		w.wantImage("matched row kept")
	})
	t.Run("R-k-different", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(3, 8, 5, 9, false)
		out := w.retain(retainWitness(blocks[8]), w.tipAt(10))
		retainWantRefusal(t, "valid differing bytes branch_data/no overwrite", out, ssqBranch, "stored selected row differs from the supplied block")
		w.wantImage("stored row kept")
		// An exact match whose stored work (99) outranks the canonical tip (11) is the K23 ORDINARY winner, not an
		// unconditional duplicate.
		w = newRetainWorld(t, ssqSpec{tip: 10})
		blocks = w.retainSide(3, 8, 5, 99, false)
		retainWant(t, "exact match winning K23 ORDINARY", w.retain(blocks[8], w.tipAt(10)), "", "ORDINARY", "OLD", old, pre, true)
		w.wantImage("winning duplicate unchanged")
	})
	t.Run("R-k-link", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(3, 8, 5, 9, false)
		w.apply([]mdbx.Mutation{w.absentRow(6, ssqMust(mdbx.HeightKey(2, 4)))})
		retainWantIntegrity(t, "missing required live link integrity", w.retain(blocks[8], w.tipAt(10)), "selected side link is absent")
		w.wantImage("missing link")
	})
	t.Run("R-k-stored-damage", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(3, 8, 5, 9, false)
		tip := w.side[8]
		w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
		out := w.retain(blocks[8], w.tipAt(10))
		retainWant(t, "optional prior stored damage: locator then complete recheck clear", out, retainCleared, "", retainNA, newT, crossed, true)
		w.wantCleared("matched stored damage clear", 4, 8)
	})
	t.Run("R-k-tip-hash", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(3, 8, 5, 9, false)
		w.setSide(func(s *mdbx.SelectedSideV1) { s.TipHash = [32]byte{0x99} })
		out := w.retain(blocks[8], w.tipAt(10))
		retainWantRefusal(t, "matched last link versus descriptor hash integrity", out, ssqIntegrity, "selected side link does not name the descriptor tip")
		w.wantImage("descriptor hash mismatch")
	})
	t.Run("R-k-tip-work", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(3, 8, 5, 9, false)
		w.setSide(func(s *mdbx.SelectedSideV1) { s.CumulativeChainwork = ssqWork(99) })
		out := w.retain(blocks[8], w.tipAt(10))
		retainWant(t, "matched last link work versus descriptor: locator then positive clear", out, retainCleared, "", retainNA, newT, crossed, true)
		w.wantCleared("descriptor work mismatch clear", 4, 8)
	})
	t.Run("R-k-cleaned", func(t *testing.T) {
		for _, history := range []bool{true, false} {
			w := newRetainWorld(t, ssqSpec{tip: 10})
			blocks := w.retainSide(5, 1_445, 1_439, 1_446, history)
			out := w.retain(blocks[7], w.tipAt(10))
			if history {
				retainWant(t, "cleaned first above F+1 with planted history stored-known", out, retainDuplicate, "", retainNA, old, pre, true)
			} else {
				retainWantRefusal(t, "missing cleaned-tail history branch_data", out, ssqBranch, "selected side ancestry below the retained rows is unusable")
			}
			w.wantImage("cleaned first")
		}
	})
	for _, c := range []struct {
		name      string
		tip, work uint64
		rows      uint16
	}{{"R-k-first-one", 6, 7, 1}, {"R-k-first-many", 8, 9, 3}} {
		t.Run(c.name, func(t *testing.T) {
			w := newRetainWorld(t, ssqSpec{tip: 10})
			blocks := w.retainSide(5, c.tip, c.rows, c.work, false)
			out := w.retain(blocks[6], w.tipAt(10))
			retainWant(t, "KNOWN_BLOCK_NOOP(STORED_NONCANONICAL)/NOT_APPLICABLE/no write", out, retainDuplicate, "", retainNA, old, pre, true)
			w.wantImage("first-row duplicate")
		})
	}
	t.Run("R-k-first-no-match", func(t *testing.T) {
		for _, side := range []struct {
			tip, work uint64
			rows      uint16
		}{{6, 8, 1}, {8, 9, 3}} {
			w := newRetainWorld(t, ssqSpec{tip: 10})
			w.retainSide(5, side.tip, side.rows, side.work, false)
			first := w.side[6]
			raw := w.child(w.canonical[5], 6, func(h [32]byte) bool { return h != first })
			retainWant(t, "NOT_SELECTED/OLD, empty Result", w.retain(raw, w.tipAt(10)), "", "NOT_SELECTED", "OLD", old, pre, true)
			w.wantImage("first-row no match")
		}
	})
	t.Run("R-k-first-different", func(t *testing.T) {
		for _, rows := range []uint16{1, 3} {
			w := newRetainWorld(t, ssqSpec{tip: 10})
			blocks := w.retainSide(5, 5+uint64(rows), rows, 6+uint64(rows), false)
			out := w.retain(retainWitness(blocks[6]), w.tipAt(10))
			retainWantRefusal(t, "healthy differing first row branch_data/no overwrite", out, ssqBranch, "stored selected row differs from the supplied block")
			w.wantImage("first row kept")
		}
	})
	t.Run("R-k-first-health", func(t *testing.T) {
		for _, c := range []struct {
			name   string
			damage func(w *ssqWorld, hash [32]byte, block []byte)
		}{
			{"stored body absent", func(w *ssqWorld, hash [32]byte, _ []byte) {
				w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(hash[:]))})
			}},
			{"stored body commitments", func(w *ssqWorld, hash [32]byte, block []byte) {
				w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(hash[:]))})
				w.apply([]mdbx.Mutation{w.literal(4, bytes.Clone(hash[:]), retainMerkle(block), false)})
			}},
			{"stored header absent", func(w *ssqWorld, hash [32]byte, _ []byte) {
				w.apply([]mdbx.Mutation{w.absentRow(3, bytes.Clone(hash[:]))})
			}},
		} {
			w := newRetainWorld(t, ssqSpec{tip: 10})
			blocks := w.retainSide(5, 8, 3, 9, false)
			c.damage(w, w.side[6], blocks[6])
			out := w.retain(blocks[6], w.tipAt(10))
			retainWant(t, c.name+": locator then complete recheck clear", out, retainCleared, "", retainNA, newT, crossed, true)
			w.wantCleared(c.name, 6, 8)
		}
		// An earlier supplied consensus failure wins even over damage of the unobserved stored body.
		w := newRetainWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(5, 6, 1, 7, false)
		hash := w.side[6]
		w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(hash[:]))})
		retainWantConsensus(t, "supplied merkle before the probe", w.retain(retainMerkle(blocks[6]), w.tipAt(10)), consensus.BLOCK_ERR_MERKLE_INVALID)
		w.wantImage("damaged first row not cleared")
	})
	t.Run("R-j1", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		w.retainSide(4, 6, 2, 9, false)
		retainWant(t, "lower work not-selected", w.retain(w.child(w.canonical[5], 6, nil), w.tipAt(10)), "", "NOT_SELECTED", "OLD", old, pre, true)
		w.wantImage("not selected by work")
	})
	t.Run("R-j2", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		w.retainSide(4, 6, 2, 7, false)
		tip := w.side[6]
		raw := w.child(w.canonical[5], 6, func(h [32]byte) bool { return bytes.Compare(h[:], tip[:]) > 0 })
		retainWant(t, "larger-tip zero effect/NOT_SELECTED", w.retain(raw, w.tipAt(10)), "", "NOT_SELECTED", "OLD", old, pre, true)
		w.wantImage("tie larger hash")
	})
	t.Run("R-t", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		w.retainSide(4, 6, 2, 6, false)
		retainWant(t, "initiating side byte-identical/REPLACE", w.retain(w.child(w.canonical[5], 6, nil), w.tipAt(10)), ssqBranch, "REPLACE", "OLD", old, pre, true)
		w.wantImage("replacement routed")
	})
	// N3 worlds: canonical tip 20 (work 21) and the mined full side 11..15 over F10 (five work-1 blocks, tip work 16); a
	// canonical-17 child (work 19) wins the side but not K23. replaced checks the healthy clear tuple and persisted
	// authority; reopenNext re-reads the bytes and proves the reopened handle refuses the next owner lookup.
	replaced := func(t *testing.T, w *ssqWorld, raw []byte, tip *mdbx.AuthorityPointV1) {
		t.Helper()
		retainWant(t, "healthy N3 clean NEW empty Result/NOT_APPLICABLE", w.replaceSide(raw, tip), "", "", retainNA, newT, crossed, true)
		if a := w.persisted(); a.Phase != mdbx.StoragePhasePruneGCV1 || a.Lifecycle != mdbx.StorageLifecycleStableV1 || a.SelectedSide != nil {
			t.Fatalf("PRUNE_GC/STABLE exact authority: %+v", a)
		}
	}
	reopenNext := func(t *testing.T, w *ssqWorld, label string) {
		t.Helper()
		w.reopen()
		w.wantImage(label + " after reopen")
		out := w.retain(w.child(w.canonical[0], 1, nil), nil)
		retainWant(t, "unclassified exact get EINVAL/not verified/no effect", out, "", "", "OLD", old, pre, false)
		retainWantEngine(t, label+": unverified owner", out.Err, "get", mdbx.EngineInvalidInput, 22, "canonical owner index is not verified")
		w.wantImage(label + ": unverified owner refusal")
	}
	t.Run("A4a", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 20})
		w.retainSide(10, 15, 5, 16, false)
		replaced(t, w, w.child(w.canonical[17], 18, nil), w.tipAt(20))
		hash := w.side[15]
		w.wantAbsent("unkept leaving header absent", 3, bytes.Clone(hash[:]))
		w.wantCleared("candidate absent and exact old-row disposition", 11, 15)
		reopenNext(t, w, "A4a")
	})
	t.Run("A4a-kept", func(t *testing.T) {
		// Side 11..15 over F10 whose rows 11..13 are the verified canonical blocks themselves (owner rows at their own
		// heights) and rows 14..15 are mined over canonical 13, tip work 16. The headers 11..13 are kept by hash at those
		// owner heights with every canonical row unchanged; the side headers 14 and 15 are deleted.
		w := newRetainWorld(t, ssqSpec{tip: 20})
		var rows []mdbx.Mutation
		var total uint64
		prev := w.canonical[10]
		for j := uint64(11); j <= 15; j++ {
			hash := w.canonical[j]
			if j > 13 {
				block := w.mined(prev, 113)
				hash = ssqHash(block)
				rows = append(rows, w.literal(3, bytes.Clone(hash[:]), block[:consensus.BLOCK_HEADER_BYTES], false), w.literal(4, bytes.Clone(hash[:]), block, false))
			}
			total += uint64(len(w.rows[string(append([]byte{4}, hash[:]...))].value))
			w.side[j] = hash
			rows = append(rows, w.literal(6, ssqMust(mdbx.HeightKey(2, j)), mdbx.ChainValue(hash, prev, ssqWork(j+1)), false))
			prev = hash
		}
		a := w.authorityValue()
		a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 2, F: 10, TipHeight: 15, TipHash: prev, CumulativeChainwork: ssqWork(16), RowCount: 5, LogicalBytes: total}
		w.apply(append(rows, w.authorityMutation(a)))
		replaced(t, w, w.child(w.canonical[17], 18, nil), w.tipAt(20))
		w.wantCleared("canonical header preserved at exact owner", 11, 15, 11, 12, 13)
		reopenNext(t, w, "A4a-kept")
	})
	t.Run("A4b", func(t *testing.T) {
		blocks := func(a *mdbx.StorageAuthorityV1) {
			a.B, a.U, a.Phase = 100, 13_780, mdbx.StoragePhasePruneGCV1
			a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanBlocksV1, GenerationID: 1, FirstHeight: 0, LastHeight: 99, NextHeight: 40}}}
		}
		// B=100, U=13780 promise a canonical tip of at least 15219 (P12); the side and candidate are the A4a witnesses.
		w := newRetainWorld(t, ssqSpec{tip: 15_219, authority: blocks})
		w.retainSide(10, 15, 5, 16, false)
		replaced(t, w, w.child(w.canonical[17], 18, nil), w.tipAt(15_219))
		a := w.authorityValue()
		a.Cleanup.Spans = append(a.Cleanup.Spans, mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: 2, FirstHeight: 11, LastHeight: 15, NextHeight: 11})
		w.authorityMutation(a)
		for j := uint64(11); j <= 15; j++ {
			hash := w.side[j]
			w.absentRow(3, bytes.Clone(hash[:]))
		}
		w.wantImage("ordered spans/progress40")
		reopenNext(t, w, "A4b")
	})
	t.Run("A4c", func(t *testing.T) {
		// The full side 1..1440 over F0 (bodies and links 1..1440 physical, tip work 1441) is rewritten to the Prepared
		// predecessor 2..1440/count1439 with SIDE(2,1,1,1) and its actual body total; a canonical-1441 child (work 1443)
		// wins it below the canonical tip 1443 (work 1444). Every body and link, row 1 included, stays.
		w := newRetainWorld(t, ssqSpec{tip: 1_443})
		blocks := w.retainSide(0, 1_440, 1_440, 1_441, false)
		a := w.tracked()
		var total uint64
		for j := uint64(2); j <= 1_440; j++ {
			total += uint64(len(blocks[j]))
		}
		a.SelectedSide.RowCount, a.SelectedSide.LogicalBytes = 1_439, total
		a.Phase, a.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 2, FirstHeight: 1, LastHeight: 1, NextHeight: 1}}}
		w.apply([]mdbx.Mutation{w.authorityMutation(a)})
		replaced(t, w, w.child(w.canonical[1_441], 1_442, nil), w.tipAt(1_443))
		a.SelectedSide, a.Cleanup.Spans[0].LastHeight = nil, 1_440
		w.authorityMutation(a)
		for j := uint64(2); j <= 1_440; j++ {
			hash := w.side[j]
			w.absentRow(3, bytes.Clone(hash[:]))
		}
		w.wantImage("single SIDE(g,1,1440,1)")
		reopenNext(t, w, "A4c")
	})
	t.Run("A4d", func(t *testing.T) {
		// Side tip work 16 ties a canonical-14 child (work 16): only a bytewise smaller hash wins.
		for _, smaller := range []bool{true, false} {
			w := newRetainWorld(t, ssqSpec{tip: 20})
			w.retainSide(10, 15, 5, 16, false)
			tip := w.side[15]
			raw := w.child(w.canonical[14], 15, func(h [32]byte) bool { return (bytes.Compare(h[:], tip[:]) < 0) == smaller })
			if !smaller {
				retainWant(t, "larger-hash tie NOT_SELECTED/no write", w.replaceSide(raw, w.tipAt(20)), "", "NOT_SELECTED", "OLD", old, pre, true)
				w.wantImage("losing tie unchanged")
				continue
			}
			retainWant(t, "smaller-tip tie exact clear", w.replaceSide(raw, w.tipAt(20)), "", "", retainNA, newT, crossed, true)
			w.wantCleared("smaller-tip tie exact clear", 11, 15)
			reopenNext(t, w, "A4d")
		}
	})
	t.Run("A4e", func(t *testing.T) {
		// After the A4a clear the fixture applies the completed SIDE predecessor image (side bodies and links 11..15
		// removed, NONE, no span, next 3); a fresh N1 then allocates generation 3 and next 4, never generation 2.
		w := newRetainWorld(t, ssqSpec{tip: 20})
		w.retainSide(10, 15, 5, 16, false)
		raw := w.child(w.canonical[17], 18, nil)
		replaced(t, w, raw, w.tipAt(20))
		w.wantCleared("A4a clear", 11, 15)
		var drained []mdbx.Mutation
		for j := uint64(11); j <= 15; j++ {
			hash := w.side[j]
			drained = append(drained, w.absentRow(4, bytes.Clone(hash[:])), w.absentRow(6, ssqMust(mdbx.HeightKey(2, j))))
		}
		a := w.authorityValue()
		w.apply(append(drained, w.authorityMutation(a)))
		retainWant(t, "fresh N1 after SIDE completion", w.retain(raw, w.tipAt(20)), retainStored, "", retainNA, newT, crossed, true)
		w.expectN1(raw, a, 3, 17, ssqWork(19))
		w.wantN1Image("fresh N1 allocates next, never the old generation", raw)
		reopenNext(t, w, "A4e")
	})
	t.Run("R-domain-node", func(t *testing.T) {
		const wrong = "selected side replacement needs a winning canonical-parent child"
		w := newRetainWorld(t, ssqSpec{tip: 20})
		retainWantRefusal(t, "Replace without a side", w.replaceSide(w.child(w.canonical[17], 18, nil), w.tipAt(20)), ssqBranch, wrong)
		w.wantImage("no-side Replace unchanged")
		blocks := w.retainSide(10, 15, 5, 16, false)
		retainWantRefusal(t, "Replace of an exact-tip child", w.replaceSide(w.child(w.side[15], 16, nil), w.tipAt(20)), ssqBranch, wrong)
		retainWantRefusal(t, "Replace has no duplicate scan", w.replaceSide(blocks[14], w.tipAt(20)), ssqBranch, "candidate parent is neither an active canonical block nor the selected tip")
		retainWantRefusal(t, "Replace control precedes the raw bound", w.replaceSide(make([]byte, mdbx.MaxBlockBytes+1), nil), ssqBranch, "candidate block exceeds MaxBlockBytes")
		w.wantImage("wrong-leaf Replace unchanged")
	})
	t.Run("R-k-first-replace", func(t *testing.T) {
		// Replace has no admitted first-row probe: the exact stored first row of a count-1 and a count-3 side is a clean
		// NOT_SELECTED with no write (Retain's known-stored result is R-k-first-one/R-k-first-many).
		for _, c := range []struct {
			tip, work uint64
			rows      uint16
		}{{6, 7, 1}, {8, 9, 3}} {
			w := newRetainWorld(t, ssqSpec{tip: 10})
			blocks := w.retainSide(5, c.tip, c.rows, c.work, false)
			retainWant(t, "Replace first-row match NOT_SELECTED/no write", w.replaceSide(blocks[6], w.tipAt(10)), "", "NOT_SELECTED", "OLD", old, pre, true)
			w.wantImage("Replace first row unchanged")
		}
	})
	// N3 preflight 2n+7223040+(1048576+2097152+2048+131072)+8388608 <= 154611151: n=67860327 clears, 67860328 refuses.
	t.Run("H11-clear", func(t *testing.T) {
		for _, n := range []int{67_860_328, 67_860_327} {
			w := newRetainWorld(t, ssqSpec{tip: 20})
			w.retainSide(10, 15, 5, 16, false)
			raw := retainLarge(t, w.canonical[17], w.ts(w.canonical[17])+120, n)
			w.absent = append(w.absent, ssqHash(raw))
			if n == 67_860_328 {
				retainWant(t, "N3 clear preflight refusal", w.replaceSide(raw, w.tipAt(20)), retainCapacity, "", "OLD", old, pre, true)
				w.wantImage("preflight refusal before planner reads")
				continue
			}
			replaced(t, w, raw, w.tipAt(20))
			w.wantCleared("largest fitting N3 candidate clears", 11, 15)
		}
	})
	t.Run("H3", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		var out SelectedSideMutationOutcome
		// With the full lane held, a grant would be refused as storage_capacity: branch_data proves no grant.
		oversize, tip := make([]byte, mdbx.MaxBlockBytes+1), w.tipAt(10)
		before, locator := bytes.Clone(oversize), *tip
		held := w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error {
			out = RetainSelectedSideMDBX(w.store, w.owner, oversize, tip)
			return nil
		})
		if held != nil {
			t.Fatalf("hold full lane: %v", held)
		}
		w.wantRaw(oversize, before)
		if *tip != locator {
			t.Fatal("oversize refusal changed the caller's tip locator")
		}
		retainWantRefusal(t, "control-only branch_data", out, ssqBranch, "candidate block exceeds MaxBlockBytes")
		w.wantImage("oversize")
		w = newRetainWorld(t, ssqSpec{tip: 10, authority: ssqPendingNone})
		retainWantRefusal(t, "control precedes the raw bound", w.retain(make([]byte, mdbx.MaxBlockBytes+1), nil), ssqRequired, "")
	})
	t.Run("H3-M", func(t *testing.T) {
		// Exactly M bytes passes the raw bound and is fully qualified: its weight, about M plus 121 per transaction,
		// exceeds MAX_BLOCK_WEIGHT at step 8.
		w := newRetainWorld(t, ssqSpec{tip: 10})
		raw := retainLarge(t, w.canonical[5], w.ts(w.canonical[5])+120, mdbx.MaxBlockBytes)
		retainWantConsensus(t, "raw=M reaches steps 1-12", w.retain(raw, w.tipAt(10)), consensus.BLOCK_ERR_WEIGHT_EXCEEDED)
		w.wantImage("raw=M unchanged")
	})
	// 3n+7223040+6422528 <= 154611151 holds up to n=46988527 (154611149) and fails at n=46988528 (154611152, G+1); the
	// G+1 refusal is NF[H11-third].
	t.Run("H11-G", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10, authority: nextTwo})
		prior := w.authorityValue()
		raw := retainLarge(t, w.canonical[5], w.ts(w.canonical[5])+120, 46_988_527)
		retainWant(t, "largest fitting candidate commits N1", w.retain(raw, w.tipAt(10)), retainStored, "", retainNA, newT, crossed, true)
		w.expectN1(raw, prior, 2, 5, ssqWork(7))
		w.wantN1Image("large N1 image", raw)
	})
	// N2 charges the exact checked linking body L: 3n+L+7223040+6422528 <= 154611151, so 3n+L <= 140965583. n=46988527
	// (3n=140965581) fits N1 but refuses here for the side tip body L >= 3; nFit=floor((140965583-L)/3) commits and
	// nFit+1 refuses. With r=(140965583-L) mod 3, 3(nFit+1)+L = 140965583+3-r, so nFit+1 commits under any charge below
	// L by at least 3-r (a header-length 116 charge included, as L > 119) and nFit refuses under any over-charge above
	// r; a smaller residue-bound deviation is not claimed.
	t.Run("H11-L", func(t *testing.T) {
		for _, step := range []int{0, 1, 2} {
			w := newRetainWorld(t, ssqSpec{tip: 10})
			blocks := w.retainSide(5, 6, 1, 7, false)
			l := len(blocks[6])
			if l <= 119 {
				t.Fatalf("side tip body %d bytes does not exceed the header bound", l)
			}
			fits, n := step == 1, 46_988_527
			if step > 0 {
				n = (140_965_583-l)/3 + step - 1
			}
			raw := retainLarge(t, w.side[6], w.ts(w.side[6])+120, n)
			if !fits {
				w.absent = append(w.absent, ssqHash(raw))
				retainWant(t, "linking length L charged/refusal", w.retain(raw, w.tipAt(10)), retainCapacity, "", "OLD", old, pre, true)
				w.wantImage("L refusal before any expected-row read")
				continue
			}
			prior := w.tracked()
			retainWant(t, "largest fitting N2 candidate with L commits", w.retain(raw, w.tipAt(10)), retainStored, "", retainNA, newT, crossed, true)
			side := mdbx.SelectedSideV1{GenerationID: 2, F: 5, TipHeight: 7, TipHash: ssqHash(raw), CumulativeChainwork: ssqWork(8), RowCount: 2, LogicalBytes: 1_000 + uint64(n)}
			w.expectN2(raw, prior, side, w.side[6])
			w.wantN1Image("large N2 image", raw)
		}
	})
	for _, c := range []struct {
		name, result string
		edit         func(*mdbx.StorageAuthorityV1)
	}{{"H4a", retainInvariant, exhausted}, {"H4b", retainBusy, both(detached, exhausted)}, {"H4c", ssqBranch, both(sideWait(9), exhausted)}} {
		t.Run(c.name, func(t *testing.T) {
			w := newRetainWorld(t, ssqSpec{tip: 10, authority: c.edit})
			out := w.retain(w.child(w.canonical[5], 6, nil), w.tipAt(10))
			retainWant(t, c.name+" fixed refusal order", out, c.result, "", "OLD", old, pre, c.result == retainBusy)
			w.wantImage(c.name + " no allocation")
		})
	}
	t.Run("H10-positive", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		w.retainSide(5, 6, 1, 7, false)
		tip := w.side[6]
		w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
		out := w.retain(w.child(tip, 7, nil), w.tipAt(10))
		retainWant(t, "complete recheck NEW/raw/error image tuple", out, retainCleared, "", retainNA, newT, crossed, true)
		w.wantCleared("positive recheck clear", 6, 6)
	})
	t.Run("H10-linking-commitments", func(t *testing.T) {
		// The optional side tip body is present and hash-bound (header unchanged) but fails its commitments: the
		// exact-tip child's linking check is a locator, never an append, and the fresh recheck completes the clear of
		// side 6..6 with the bad body and its link kept and the unkept header removed.
		w := newRetainWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(5, 6, 1, 7, false)
		tip := w.side[6]
		w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
		w.apply([]mdbx.Mutation{w.literal(4, bytes.Clone(tip[:]), retainMerkle(blocks[6]), false)})
		out := w.retain(w.child(tip, 7, nil), w.tipAt(10))
		retainWant(t, "commitment-invalid linking body: locator then complete recheck clear", out, retainCleared, "", retainNA, newT, crossed, true)
		w.wantCleared("commitment-invalid linking body clear", 6, 6)
		w.reopen()
		w.wantImage("commitment-invalid linking body clear after reopen")
		out = w.retain(w.child(w.canonical[4], 5, nil), w.tipAt(10))
		retainWant(t, "unclassified exact get EINVAL/not verified/no effect", out, "", "", "OLD", old, pre, false)
		retainWantEngine(t, "unverified owner after clear", out.Err, "get", mdbx.EngineInvalidInput, 22, "canonical owner index is not verified")
		w.wantImage("unverified owner refusal after clear")
	})
	t.Run("H12-typednil", func(t *testing.T) {
		var typed *selectedSideQualificationError
		var tx *consensus.TxError
		descendant := &selectedSideQualificationError{Result: ssqBranch, Cause: (*mdbx.EngineError)(nil)}
		for _, leaf := range []error{typed, tx, descendant} {
			if got := consensus.ClassifySelectedSideFailureMDBX(leaf, pre, "", leaf, ssqBranch); got != retainInvariant {
				t.Fatalf("fail-closed invariant: nil leaf or descendant %T classified %q", leaf, got)
			}
		}
	})
	t.Run("H12-unmatched", func(t *testing.T) {
		abort := &mdbx.EngineError{Class: mdbx.EngineIO, Operation: "abort", Code: 5}
		leaf := &selectedSideQualificationError{Result: ssqBranch, Cause: errors.New("bound")}
		var typed *selectedSideQualificationError
		// The producer owner: every value goes through this attempt's bind, then its own projection with a joined
		// nonterminal abort cause.
		for _, c := range []struct {
			name, want string
			leaf       error
		}{
			{"direct qualifier refusal binds its finite result", ssqBranch, leaf},
			{"direct TxError binds its own code", "CONSENSUS_INVALID(BLOCK_ERR_MERKLE_INVALID)", &consensus.TxError{Code: consensus.BLOCK_ERR_MERKLE_INVALID}},
			{"wrapped qualifier refusal binds nothing", retainInvariant, fmt.Errorf("wrapped: %w", leaf)},
			{"foreign error binds nothing", retainInvariant, errors.New("foreign")},
			{"arbitrary StateMismatch EngineError binds nothing", retainInvariant, &mdbx.EngineError{Class: mdbx.EngineStateMismatch, Operation: "update", Code: -30799}},
			{"typed-nil qualifier binds nothing", retainInvariant, typed},
			{"cause-less qualifier binds nothing", retainInvariant, &selectedSideQualificationError{Result: ssqBranch}},
			{"foreign-result qualifier binds nothing", retainInvariant, &selectedSideQualificationError{Result: retainBusy, Cause: errors.New("busy")}},
		} {
			a := &selectedRetainAttempt{ran: true, sentinel: errors.New("decision")}
			returned := a.bind(c.leaf)
			out, request := a.project(SelectedSideMutationOutcome{Truth: old, Stage: pre, Err: errors.Join(returned, abort)})
			if out.Result != c.want || request != nil || returned != c.leaf { //nolint:errorlint // The exact returned leaf.
				t.Fatalf("%s: classified %q", c.name, out.Result)
			}
		}
		// The sentinel binds the empty skip and clears the stale read class, so its abort IO is storage_io.
		a := &selectedRetainAttempt{ran: true, sentinel: errors.New("decision"), resource: ssqBranch}
		out, _ := a.project(SelectedSideMutationOutcome{Truth: old, Stage: pre, Err: errors.Join(a.bind(a.sentinel), abort)})
		if out.Result != retainStorageIO {
			t.Fatalf("sentinel abort classified %q", out.Result)
		}
		// The consumer substitutes only the exact bound occurrence: another identical-shape refusal stays an invariant.
		other := &selectedSideQualificationError{Result: ssqBranch, Cause: errors.New("other")}
		if got := consensus.ClassifySelectedSideFailureMDBX(errors.Join(other, abort), pre, "", leaf, ssqBranch); got != retainInvariant {
			t.Fatalf("unmatched leaf invariant/no invented result: %q", got)
		}
		if got := consensus.ClassifySelectedSideFailureMDBX(leaf, pre, "", leaf, retainBusy); got != retainInvariant {
			t.Fatalf("result outside the finite domain bound: %q", got)
		}
		invalid := &mdbx.EngineError{Class: mdbx.EngineInvalidInput, Operation: "get", Code: 22}
		if got := consensus.ClassifySelectedSideFailureMDBX(errors.Join(invalid, abort), pre, ssqCanonical, nil, ""); got != "" {
			t.Fatalf("unverified InvalidInput stays empty-first: %q", got)
		}
	})
}
