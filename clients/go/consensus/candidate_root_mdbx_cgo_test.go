//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

type candidateScene struct {
	world   *btWorld
	seed    blockTreeRequestV1
	parent  mdbx.TreeEndpointV1
	entries map[Outpoint]UtxoEntry
	funding Outpoint
	other   Outpoint
	key     *MLDSA87Keypair
	cov     []byte
}

func newCandidateScene(t *testing.T, height uint64) candidateScene {
	t.Helper()
	w := btNew(t)
	key := icbKeyV1(t)
	cov := p2pkCovenantDataForPubkey(key.PubkeyBytes())
	seed, cb, ordinary := icbSeedV1(t, w, cov, height)
	a, b := Outpoint{Txid: ordinary.id}, Outpoint{Txid: ordinary.id, Vout: 1}
	entries := map[Outpoint]UtxoEntry{
		{Txid: cb.id}: btEntry(7, 0, validP2PKCovenantData(), height-1, true),
		a:             btEntry(1000, 0, cov, height-1, false),
		b:             btEntry(2000, 0, cov, height-1, false),
	}
	return candidateScene{w, seed, seed.Endpoint, entries, a, b, key, cov}
}

func candidateInput(t *testing.T, raw []byte, parent mdbx.TreeEndpointV1) CandidateRootInput {
	t.Helper()
	height := parent.Height + 1
	frozen, err := FreezeCandidateRootRotation(height, DefaultRotationProvider{})
	logicalMDBXAssert(t, err == nil, "freeze candidate rotation: %v", err)
	registry, err := NewCandidateRootCapRegistry(nil)
	logicalMDBXAssert(t, err == nil, "candidate cap registry: %v", err)
	return CandidateRootInput{
		Raw: raw, Selection: mdbx.CandidateRootParentV1{DatabaseID: [32]byte{7}, Generation: 1, Height: height, Parent: parent},
		ExpectedTarget: POW_LIMIT, ParentTimestamps: slices.Repeat([]uint64{blockStepsMedian}, int(min(height, 11))),
		CapRegistry: registry, Registry: DefaultSuiteRegistry(), Rotation: frozen,
	}
}

func candidateFrame(t *testing.T, parent mdbx.TreeEndpointV1, payout uint64, others ...[]byte) ([]byte, Outpoint) {
	t.Helper()
	commit := initial148BlockWitnessCommit(t, others...)
	cb := coinbaseTxWithOutputs(uint32(parent.Height+1), []testOutput{
		{value: payout, covenantType: 0, covenantData: validP2PKCovenantData()},
		{covenantType: 2, covenantData: commit[:]},
	})
	raw := initial148BlockFrame(t, append([][]byte{cb}, others...), func(h *initial148BlockHead) { h.parent = parent.BlockHash })
	return raw, Outpoint{Txid: testTxID(t, cb)}
}

func (s candidateScene) spend(t *testing.T, nonce uint64, input Outpoint, old, next uint64) ([]byte, Outpoint) {
	t.Helper()
	tx := inputViewTx(nonce, input)
	tx.Outputs[0] = TxOutput{Value: next, CovenantType: 0, CovenantData: s.cov}
	raw := icbSignV1(t, s.key, tx, old)
	return raw, Outpoint{Txid: testTxID(t, raw)}
}

func (s candidateScene) body(t *testing.T, spends int, payout uint64) (CandidateRootInput, [32]byte) {
	t.Helper()
	final := maps.Clone(s.entries)
	h := s.parent.Height + 1
	var other [][]byte
	if spends > 0 {
		raw, created := s.spend(t, 11, s.funding, 1000, 990)
		other = append(other, raw)
		delete(final, s.funding)
		if spends > 1 {
			raw, created = s.spend(t, 12, created, 990, 980)
			other = append(other, raw)
			final[created] = btEntry(980, 0, s.cov, h, false)
		} else {
			final[created] = btEntry(990, 0, s.cov, h, false)
		}
	}
	raw, cb := candidateFrame(t, s.parent, payout, other...)
	final[cb] = btEntry(payout, 0, validP2PKCovenantData(), h, true)
	return candidateInput(t, raw, s.parent), canonicalUTXORoot(final)
}

func candidateRootOK(t *testing.T, r *mdbx.Reader, o *mdbx.OperationReservationOwner, in CandidateRootInput, want [32]byte) {
	t.Helper()
	got, err := DeriveCandidateUTXORootV1(r, o, in)
	logicalMDBXAssert(t, err == nil && got == want, "candidate digest %x/%v, want %x", got, err, want)
}

func candidateTxError(t *testing.T, r *mdbx.Reader, o *mdbx.OperationReservationOwner, in CandidateRootInput, code ErrorCode, diagnostic string) {
	t.Helper()
	got, err := DeriveCandidateUTXORootV1(r, o, in)
	var tx *TxError
	logicalMDBXAssert(t, got == [32]byte{} && errors.As(err, &tx) && tx != nil && any(err) == any(tx) && tx.Code == code && tx.Msg == diagnostic,
		"candidate first result %x/%v, want %s/%q", got, err, code, diagnostic)
	_, _, logical := InspectCandidateRootFailure(err)
	logicalMDBXAssert(t, !logical, "candidate transaction error classified as logical state failure: %v", err)
}

func candidateView(t *testing.T, w *btWorld, use func(*mdbx.Reader)) {
	t.Helper()
	err := w.s.View(func(r *mdbx.Reader) error {
		use(r)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "candidate View: %v", err)
}

func TestCandidateRootResult(t *testing.T) {
	s := newCandidateScene(t, 5)
	full, want := s.body(t, 2, 20)
	coinbase, coinbaseWant := s.body(t, 0, 1)
	t.Run("unsolved", func(t *testing.T) { candidateUnsolved(t, s, full, want) })
	t.Run("header_tail", func(t *testing.T) {
		first, second := full, full
		first.Raw, second.Raw = bytes.Clone(full.Raw), bytes.Clone(full.Raw)
		copy(first.Raw[108:140], want[:])
		copy(second.Raw[108:148], bytes.Repeat([]byte{0xa5}, 40))
		candidateView(t, s.world, func(r *mdbx.Reader) {
			candidateRootOK(t, r, s.world.owner, first, want)
			candidateRootOK(t, r, s.world.owner, second, want)
		})
		initial148Unchanged(t, first.Raw[148:], second.Raw[148:])
	})
	t.Run("final_map", func(t *testing.T) {
		candidateUnchanged(t, s, full, want)
	})
	t.Run("coinbase_only", func(t *testing.T) {
		candidateView(t, s.world, func(r *mdbx.Reader) { candidateRootOK(t, r, s.world.owner, coinbase, coinbaseWant) })
	})
	t.Run("membership", func(t *testing.T) { candidateMembership(t, s) })
	t.Run("active_simplicity", candidateActiveSimplicity)
	t.Run("variant", func(t *testing.T) {
		t.Run("payout", func(t *testing.T) { candidateVariant(t, s, full, want, 21, 2) })
		t.Run("without_last_spend", func(t *testing.T) { candidateVariant(t, s, full, want, 20, 1) })
	})
}

func candidateActiveSimplicity(t *testing.T) {
	w := btNew(t)
	f := icbH5VariantV1(t, w, icbH5OptsV1{vault: true, simplicity: 1})
	in := candidateInput(t, f.in.Raw, f.in.Parent)
	in.AlreadyGenerated, in.ChainID = f.in.AlreadyGenerated, f.in.ChainID
	rotation, err := FreezeCandidateRootRotation(f.h, activeSimplicityRotation(in.ChainID, 1))
	logicalMDBXAssert(t, err == nil, "freeze candidate Simplicity deployment: %v", err)
	in.Rotation = rotation
	want := icbRootV1(f.finalLeaves)
	candidateView(t, w, func(r *mdbx.Reader) { candidateRootOK(t, r, w.owner, in, want) })
}

func candidateVariant(t *testing.T, s candidateScene, in CandidateRootInput, original [32]byte, payout uint64, spends int) {
	t.Helper()
	txs := candidateFullSpends(t, in.Raw)
	in.Raw, _ = candidateFrame(t, s.parent, payout, txs[:spends]...)
	final := maps.Clone(s.entries)
	delete(final, s.funding)
	frame, err := ParseInitial148BlockBytes(in.Raw)
	logicalMDBXAssert(t, err == nil, "candidate variant frame: %v", err)
	final[Outpoint{Txid: frame.Txids[0]}] = btEntry(payout, 0, validP2PKCovenantData(), 5, true)
	value := uint64(990)
	if spends == 2 {
		value = 980
	}
	final[Outpoint{Txid: testTxID(t, txs[spends-1])}] = btEntry(value, 0, s.cov, 5, false)
	want := canonicalUTXORoot(final)
	logicalMDBXAssert(t, want != original, "candidate variant has the original oracle digest")
	candidateView(t, s.world, func(r *mdbx.Reader) { candidateRootOK(t, r, s.world.owner, in, want) })
}

func candidateFullSpends(t *testing.T, raw []byte) [2][]byte {
	t.Helper()
	logicalMDBXAssert(t, len(raw) >= 149 && raw[148] == 3, "candidate variant requires three framed transactions")
	offset := 149
	_, _, _, _, err := parseBlockTx(raw, &offset)
	logicalMDBXAssert(t, err == nil, "candidate variant coinbase: %v", err)
	var spends [2][]byte
	for i := range spends {
		start := offset
		_, _, _, _, err := parseBlockTx(raw, &offset)
		logicalMDBXAssert(t, err == nil, "candidate variant spend %d: %v", i, err)
		spends[i] = raw[start:offset]
	}
	logicalMDBXAssert(t, offset == len(raw), "candidate variant trailing bytes")
	return spends
}

func candidateUnsolved(t *testing.T, s candidateScene, in CandidateRootInput, want [32]byte) {
	t.Helper()
	in.Raw = bytes.Clone(in.Raw)
	in.ExpectedTarget[0] = 0x7f
	copy(in.Raw[76:108], in.ExpectedTarget[:])
	for Initial148PowCheck(in.Raw[:148], in.ExpectedTarget) == nil {
		nonce := binary.LittleEndian.Uint64(in.Raw[140:148])
		binary.LittleEndian.PutUint64(in.Raw[140:148], nonce+1)
	}
	initial148BlockWantError(t, "unsolved input", Initial148PowCheck(in.Raw[:148], in.ExpectedTarget), "BLOCK_ERR_POW_INVALID", "pow invalid")
	candidateView(t, s.world, func(r *mdbx.Reader) {
		root, err := DeriveCandidateUTXORootV1(r, s.world.owner, in)
		logicalMDBXAssert(t, err == nil && root == want, "unsolved candidate digest %x/%v, want %x", root, err, want)
		candidateSolved(t, s, r, in, root)
	})
}

func candidateSolved(t *testing.T, s candidateScene, reader *mdbx.Reader, in CandidateRootInput, root [32]byte) {
	t.Helper()
	parsed, err := ParseInitial148HeaderBytes(in.Raw[:148])
	logicalMDBXAssert(t, err == nil, "solved header parse: %v", err)
	header := initial148BlockHead{version: parsed.Version, parent: parsed.PrevBlockHash, merkle: parsed.MerkleRoot, target: parsed.Target, timestamp: parsed.Timestamp, root: root}
	solved := append(initial148BlockMine(t, header), in.Raw[148:]...)
	complete := initial148CompleteBlockInputV1{
		Raw: solved, Height: in.Selection.Height, Parent: in.Selection.Parent, ParentHash: in.Selection.Parent.BlockHash,
		ExpectedTarget: in.ExpectedTarget, ParentTimestamps: in.ParentTimestamps, DatabaseID: in.Selection.DatabaseID, Generation: in.Selection.Generation,
		CapRegistry: &in.CapRegistry.registry, Registry: in.Registry, Rotation: in.Rotation.rotation,
		Endpoint: mdbx.TreeEndpointV1{Kind: 1, Height: in.Selection.Height, BlockHash: sha3.Sum256(solved[:148]), CumulativeChainwork: [40]byte{39: 100}},
	}
	err = s.world.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		_, err := withInitial148CompleteBlockV1(a, complete, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
			result, err := validate(reader)
			logicalMDBXAssert(t, err == nil && result != nil && result.summary.TxCount == 3, "solved composer: %v", err)
			return err
		})
		return err
	})
	logicalMDBXAssert(t, err == nil, "solved account: %v", err)
}

func candidateUnchanged(t *testing.T, s candidateScene, in CandidateRootInput, want [32]byte) {
	t.Helper()
	before, err := s.world.s.Inspect()
	logicalMDBXAssert(t, err == nil, "candidate prestate: %v", err)
	raw := bytes.Clone(in.Raw)
	candidateView(t, s.world, func(r *mdbx.Reader) {
		rows := candidateParentSnapshot(t, r, s.seed)
		candidateRootOK(t, r, s.world.owner, in, want)
		candidateRootOK(t, r, s.world.owner, in, want)
		tip, err := r.CanonicalTipV1(s.seed.Generation)
		logicalMDBXAssert(t, err == nil && tip != nil && tip.Height == s.parent.Height && tip.BlockHash == s.parent.BlockHash, "canonical tip after candidate calls: %+v/%v", tip, err)
		for _, row := range rows {
			candidateReadExact(t, r, row.rank, row.key, row.value)
		}
		candidateAssertParentRows(t, r, s)
	})
	after, err := s.world.s.Inspect()
	logicalMDBXAssert(t, err == nil && before.RecentTxnID == after.RecentTxnID && before.DBIs == after.DBIs, "candidate mutated store: %v", err)
	initial148Unchanged(t, in.Raw, raw)
	btReservationsReleased(t, s.world.owner)
}

type candidateRowSnapshot struct {
	rank       uint8
	key, value []byte
}

func candidateParentSnapshot(t *testing.T, r *mdbx.Reader, seed blockTreeRequestV1) []candidateRowSnapshot {
	t.Helper()
	tip, err := mdbx.HeightKey(seed.Generation, seed.Height)
	logicalMDBXAssert(t, err == nil, "snapshot tip key: %v", err)
	index, err := mdbx.CanonicalOwnerKey(seed.Generation, seed.Block)
	logicalMDBXAssert(t, err == nil, "snapshot owner key: %v", err)
	rows := []candidateRowSnapshot{
		{rank: 0, key: []byte{0}},
		{rank: 0, key: []byte{1}},
		{rank: 0, key: []byte{2}},
		{rank: 0, key: []byte{3}},
		{rank: 0, key: btMeta(16, 1)},
		{rank: 0, key: btMeta(16, 2)},
		{rank: 0, key: btMeta(17, 1)},
		{rank: 0, key: btMeta(17, 2)},
		{rank: 2, key: tip},
		{rank: 3, key: seed.Block[:]},
		{rank: 4, key: seed.Block[:]},
		{rank: 5, key: mdbx.UndoManifestKey(seed.Block)},
		{rank: 7, key: index},
	}
	for i := range rows {
		row := &rows[i]
		value, found, err := r.Get(mdbx.TreeSchemaV1DBIs()[row.rank], row.key)
		logicalMDBXAssert(t, err == nil && found, "snapshot row %d/%x: %t/%v", row.rank, row.key, found, err)
		row.value = value
	}
	return rows
}

func candidateAssertParentRows(t *testing.T, r *mdbx.Reader, s candidateScene) {
	t.Helper()
	leaves := map[[36]byte][]byte{}
	for op, row := range s.entries {
		icbLeafKindV1(leaves, op, row.Value, row.CovenantType, row.CovenantData, row.CreationHeight, row.CreatedByCoinbase)
		candidateReadExact(t, r, 1, btUTXOKey(1, op), btValue(btFrame(row.Value, row.CovenantType, row.CovenantData), row.CreationHeight, row.CreatedByCoinbase))
	}
	root, present, err := r.ReadTreeRootBindingV1(1)
	logicalMDBXAssert(t, err == nil && present && root.RootDigest == canonicalUTXORoot(s.entries) && root.Endpoint == s.parent, "candidate changed binding: %v/%+v", err, root)
	icbRootV1(leaves, func(id mdbx.TreeNodeIDV1, value []byte) {
		key, err := mdbx.TreeNodeKey(1, id)
		logicalMDBXAssert(t, err == nil, "parent node key: %v", err)
		candidateReadExact(t, r, 8, key, value)
	})
}

func candidateReadExact(t *testing.T, r *mdbx.Reader, rank uint8, key, want []byte) {
	t.Helper()
	got, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[rank], key)
	logicalMDBXAssert(t, err == nil && present == (want != nil) && bytes.Equal(got, want), "candidate row %d/%x: %x/%v/%v, want %x", rank, key, got, present, err, want)
}

func candidateMembership(t *testing.T, s candidateScene) {
	t.Helper()
	id, payload := [32]byte{0x75}, []byte("B")
	hash := sha3.Sum256(payload)
	commit, chunk := inputViewTx(17, s.funding), inputViewTx(18, s.other)
	commit.TxKind, commit.DaCommitCore = 1, &DaCommitCore{DaID: id, ChunkCount: 1}
	commit.Outputs = []TxOutput{{Value: 990, CovenantType: 0, CovenantData: s.cov}, {CovenantType: 0x0103, CovenantData: hash[:]}}
	chunk.TxKind, chunk.DaChunkCore, chunk.DaPayload = 2, &DaChunkCore{DaID: id, ChunkHash: hash}, payload
	chunk.Outputs = nil
	first, second := icbSignV1(t, s.key, commit, 1000), icbSignV1(t, s.key, chunk, 2000)
	raw, cb := candidateFrame(t, s.parent, 1, first, second)
	final := maps.Clone(s.entries)
	delete(final, s.funding)
	delete(final, s.other)
	final[cb] = btEntry(1, 0, validP2PKCovenantData(), 5, true)
	final[Outpoint{Txid: testTxID(t, first)}] = btEntry(990, 0, s.cov, 5, false)
	candidateView(t, s.world, func(r *mdbx.Reader) {
		candidateRootOK(t, r, s.world.owner, candidateInput(t, raw, s.parent), canonicalUTXORoot(final))
	})
}

type candidateOrderCase struct {
	name string
	raw  []byte
	code ErrorCode
	msg  string
}

func TestCandidateRootOrder(t *testing.T) {
	s := newCandidateScene(t, 5)
	for _, row := range append(candidateHeaderCases(t, s), candidateBlockResourceCases(t, s)...) {
		t.Run(row.name, func(t *testing.T) {
			in := candidateInput(t, row.raw, s.parent)
			next, want := s.body(t, 0, 1)
			candidateView(t, s.world, func(r *mdbx.Reader) {
				candidateTxError(t, r, s.world.owner, in, row.code, row.msg)
				candidateRootOK(t, r, s.world.owner, next, want)
			})
		})
	}
	t.Run("transaction_before_subsidy", func(t *testing.T) { candidateSpendOrder(t, s) })
	t.Run("subsidy_before_law", func(t *testing.T) { candidateSubsidyBeforeLaw(t) })
	t.Run("already_generated", candidateAlreadyGenerated)
	t.Run("da_bytes", func(t *testing.T) { candidateDABytes(t, s, false) })
	t.Run("timestamp_before_da_bytes", func(t *testing.T) { candidateDABytes(t, s, true) })
}

func candidateHeaderCases(t *testing.T, s candidateScene) []candidateOrderCase {
	t.Helper()
	in, _ := s.body(t, 0, 1)
	target, link := bytes.Clone(in.Raw), bytes.Clone(in.Raw)
	target[76], target[4] = 0x7f, target[4]^1
	link[4], link[36] = link[4]^1, link[36]^1
	witness := candidateWitnessFault(t, s, nil)
	merkle := bytes.Clone(witness)
	merkle[36] ^= 1
	commit := initial148BlockWitnessCommit(t)
	wrong := commit
	wrong[0] ^= 1
	return []candidateOrderCase{
		{"trailing_bytes", append(target, 0), "BLOCK_ERR_PARSE", "trailing bytes after tx list"},
		{"target", target, "BLOCK_ERR_TARGET_INVALID", "target mismatch"},
		{"linkage", link, "BLOCK_ERR_LINKAGE_INVALID", "prev_block_hash mismatch"},
		{"merkle", merkle, "BLOCK_ERR_MERKLE_INVALID", "merkle_root mismatch"},
		{"witness", witness, "BLOCK_ERR_WITNESS_COMMITMENT", "coinbase witness commitment missing or duplicated"},
		{"witness_wrong_bytes", candidateWitnessFault(t, s, [][32]byte{wrong}), "BLOCK_ERR_WITNESS_COMMITMENT", "coinbase witness commitment missing or duplicated"},
		{"witness_duplicate", candidateWitnessFault(t, s, [][32]byte{commit, commit}), "BLOCK_ERR_WITNESS_COMMITMENT", "coinbase witness commitment missing or duplicated"},
	}
}

func candidateWitnessFault(t *testing.T, s candidateScene, commits [][32]byte) []byte {
	t.Helper()
	outs := []testOutput{{value: 1, covenantType: 0, covenantData: validP2PKCovenantData()}}
	for i := range commits {
		outs = append(outs, testOutput{covenantType: 2, covenantData: commits[i][:]})
	}
	cb := coinbaseTxWithOutputs(5, outs)
	return initial148BlockFrame(t, [][]byte{cb}, func(h *initial148BlockHead) {
		h.parent, h.timestamp = s.parent.BlockHash, blockStepsMedian
	})
}

func candidateBlockResourceCases(t *testing.T, s candidateScene) []candidateOrderCase {
	t.Helper()
	a, b, p := blockStepsIDs[0], blockStepsIDs[1], []byte{0x42}
	good, bad := blockStepsChunk(a, 0, p, sha3.Sum256(p)), blockStepsChunk(b, 0, p, [32]byte{})
	invalidPayload := blockStepsCommit(a, 1, blockStepsDAOut([32]byte{3}))
	frame := func(txs ...[]byte) []byte {
		return initial148BlockFrame(t, append([][]byte{initial148BlockCoinbase(t, txs...)}, txs...), func(h *initial148BlockHead) { h.parent = s.parent.BlockHash })
	}
	anchor := frame(blockStepsAnchors(131072-31), bad)
	weight := frame(append(blockStepsWeighted(t, 68_000_001), bad)...)
	old, future := bytes.Clone(weight), bytes.Clone(anchor)
	binary.LittleEndian.PutUint64(old[68:76], blockStepsMedian)
	binary.LittleEndian.PutUint64(future[68:76], blockStepsMedian+7201)
	return []candidateOrderCase{
		{"timestamp_old", old, "BLOCK_ERR_TIMESTAMP_OLD", "timestamp <= MTP median"},
		{"timestamp_future", future, "BLOCK_ERR_TIMESTAMP_FUTURE", "timestamp exceeds future drift"},
		{"weight", weight, "BLOCK_ERR_WEIGHT_EXCEEDED", "block weight exceeded"},
		{"anchor_bytes", anchor, "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED", "anchor bytes exceeded"},
		{"chunk_hash", frame(invalidPayload, good, bad), "BLOCK_ERR_DA_CHUNK_HASH_INVALID", "chunk_hash mismatch"},
		{"set", frame(invalidPayload, good, blockStepsChunk(b, 0, p, sha3.Sum256(p))), "BLOCK_ERR_DA_SET_INVALID", "DA chunks without DA commit"},
		{"incomplete", frame(blockStepsCommit(a, 2, blockStepsDAOut([32]byte{3})), good), "BLOCK_ERR_DA_INCOMPLETE", "DA chunk count mismatch"},
		{"payload", frame(invalidPayload, good), "BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID", "payload commitment mismatch"},
	}
}

func candidateDABytes(t *testing.T, s candidateScene, old bool) {
	t.Helper()
	chunks := blockStepsDABytes(32_000_001)
	cb := initial148BlockCoinbase(t, chunks...)
	var payload int
	weight := blockStepsWeight(t, cb)
	for _, raw := range chunks {
		chunk, _, _, _, err := ParseTx(raw)
		logicalMDBXAssert(t, err == nil, "DA byte fixture parse: %v", err)
		payload += len(chunk.DaPayload)
		weight += blockStepsWeight(t, raw)
	}
	first, _, _, _, err := ParseTx(chunks[0])
	logicalMDBXAssert(t, err == nil && sha3.Sum256(first.DaPayload) != first.DaChunkCore.ChunkHash && payload == 32_000_001 && weight < 68_000_000,
		"DA byte fixture payload/weight/hash: %d/%d/%v", payload, weight, err)
	raw := initial148BlockFrame(t, append([][]byte{cb}, chunks...), func(h *initial148BlockHead) { h.parent = s.parent.BlockHash })
	code, diagnostic := ErrorCode("BLOCK_ERR_WEIGHT_EXCEEDED"), "DA bytes exceeded"
	if old {
		binary.LittleEndian.PutUint64(raw[68:76], blockStepsMedian)
		code, diagnostic = "BLOCK_ERR_TIMESTAMP_OLD", "timestamp <= MTP median"
	}
	in := candidateInput(t, raw, s.parent)
	next, want := s.body(t, 0, 1)
	candidateView(t, s.world, func(r *mdbx.Reader) {
		candidateTxError(t, r, s.world.owner, in, code, diagnostic)
		candidateRootOK(t, r, s.world.owner, next, want)
	})
}

func candidateSpendOrder(t *testing.T, s candidateScene) {
	t.Helper()
	in, next, want := candidateSpendOrderInputs(t, s)
	candidateView(t, s.world, func(r *mdbx.Reader) {
		candidateTxError(t, r, s.world.owner, in, "TX_ERR_MISSING_UTXO", "utxo not found")
		candidateRootOK(t, r, s.world.owner, next, want)
	})
}

func candidateSpendOrderInputs(t *testing.T, s candidateScene) (CandidateRootInput, CandidateRootInput, [32]byte) {
	t.Helper()
	first, _ := s.spend(t, 1, s.funding, 1000, 990)
	op := Outpoint{Txid: [32]byte{0x99}}
	second, _ := s.spend(t, 2, op, 990, 980)
	raw, _ := candidateFrame(t, s.parent, 4_900_000_000_000_000, first, second)
	next, want := s.body(t, 0, 1)
	return candidateInput(t, raw, s.parent), next, want
}

func candidateSubsidyBeforeLaw(t *testing.T) {
	t.Helper()
	w, in, next, want := candidateSubsidyOrderInputs(t)
	candidateView(t, w, func(r *mdbx.Reader) {
		candidateTxError(t, r, w.owner, in, "BLOCK_ERR_SUBSIDY_EXCEEDED", "coinbase outputs exceed subsidy+fees bound")
		candidateRootOK(t, r, w.owner, next, want)
	})
}

func candidateSubsidyOrderInputs(t *testing.T) (*btWorld, CandidateRootInput, CandidateRootInput, [32]byte) {
	t.Helper()
	w, in, _, funding := candidateGrowthSetup(t, true)
	in.Raw, _ = candidateFrame(t, in.Selection.Parent, 4_900_000_000_000_000, funding.spends...)
	next, want := candidateGrowthCoinbase(t, in, funding.parents)
	return w, in, next, want
}

func candidateAlreadyGenerated(t *testing.T) {
	s := newCandidateScene(t, 2)
	in, _ := s.body(t, 0, 4_672_999_694)
	next, want := s.body(t, 0, 4_672_999_693)
	in.AlreadyGenerated = Uint128{Lo: 4_673_004_150}
	next.AlreadyGenerated = in.AlreadyGenerated
	candidateView(t, s.world, func(r *mdbx.Reader) {
		candidateTxError(t, r, s.world.owner, in, "BLOCK_ERR_SUBSIDY_EXCEEDED", "coinbase outputs exceed subsidy+fees bound")
		candidateRootOK(t, r, s.world.owner, next, want)
	})
}

func candidateTipRows(t *testing.T, parent mdbx.TreeEndpointV1, generation uint64) (mdbx.Mutation, mdbx.Mutation) {
	t.Helper()
	key, err := mdbx.HeightKey(generation, parent.Height)
	logicalMDBXAssert(t, err == nil, "candidate canonical tip key: %v", err)
	ownerKey, err := mdbx.CanonicalOwnerKey(generation, parent.BlockHash)
	logicalMDBXAssert(t, err == nil, "candidate canonical owner key: %v", err)
	return btMutation(2, key, mdbx.ChainValue(parent.BlockHash, [32]byte{}, parent.CumulativeChainwork)),
		btMutation(7, ownerKey, mdbx.CanonicalOwnerValue(parent.Height))
}

func candidateSeedGrowth(t *testing.T, w *btWorld, parent mdbx.TreeEndpointV1, cov []byte) ([32]byte, map[Outpoint]UtxoEntry) {
	t.Helper()
	frames := slices.Repeat([][]byte{btFrame(2000, COV_TYPE_P2PK, cov)}, 9)
	coinbase := btTransaction(1, 0, []Outpoint{{Txid: [32]byte{0x77}}}, frames, nil, []byte{0}, nil)
	seed := btRequest(btBody(148, 8, [32]byte{}, coinbase), 0)
	seed.Kind = mdbx.TreeKindFirstGenesisV1
	result, _, _ := w.run(t, []blockTreeRequestV1{seed}, nil)
	result.want(t, 2, 3, -1)
	logicalMDBXAssert(t, result.err == nil, "growth funding genesis: %v", result.err)
	entries := make(map[Outpoint]UtxoEntry, len(frames))
	for i := range frames {
		entries[Outpoint{Txid: coinbase.id, Vout: uint32(i)}] = btEntry(2000, COV_TYPE_P2PK, cov, 0, true)
	}
	var binding mdbx.RootBindingV1
	candidateView(t, w, func(r *mdbx.Reader) {
		root, present, err := r.ReadTreeRootBindingV1(1)
		logicalMDBXAssert(t, err == nil && present && root.Endpoint == seed.Endpoint, "growth funding binding: %+v/%t/%v", root, present, err)
		binding = root
	})
	binding.Endpoint = parent
	encoded, err := binding.Encode()
	logicalMDBXAssert(t, err == nil, "candidate seed binding: %v", err)
	rootRow := btMutation(0, btMeta(0x11, 1), encoded)
	rootRow.BeforePresent = true
	tip, owner := candidateTipRows(t, parent, 1)
	w.pair(t, rootRow, tip, owner)
	stepTreeStateV1(t, w, 1, parent, entries)
	return coinbase.id, entries
}

type candidateGrowthFunding struct {
	parents map[Outpoint]UtxoEntry
	spends  [][]byte
}

func candidateGrowthSetup(t *testing.T, over bool) (*btWorld, CandidateRootInput, [32]byte, candidateGrowthFunding) {
	t.Helper()
	return candidateGrowthAtHeight(t, over, 200)
}

func candidateGrowthAtHeight(t *testing.T, over bool, height uint64) (*btWorld, CandidateRootInput, [32]byte, candidateGrowthFunding) {
	t.Helper()
	kp := icbKeyV1(t)
	parent := mdbx.TreeEndpointV1{Kind: 1, Height: height - 1, BlockHash: [32]byte{0xd2}, CumulativeChainwork: [40]byte{38: 2, 39: 1}}
	w := btNew(t)
	fundingID, entries := candidateSeedGrowth(t, w, parent, p2pkCovenantDataForPubkey(kp.PubkeyBytes()))
	census := logicalGrowthEqual
	s1, events := uint64(773921), 8674
	if over {
		census, s1, events = logicalGrowthOver, 773922, 8691
	}
	txs := logicalGrowthTxs(t, kp, [32]byte{}, census)
	for i, tx := range txs {
		tx.Inputs[0].PrevTxid, tx.Inputs[0].PrevVout = fundingID, uint32(i)
		tx.Witness[0] = signP2PKInputWitness(t, tx, 0, 2000, [32]byte{}, kp)
	}
	raws := logicalGrowthMarshal(t, txs)
	final := candidateGrowthOutputs(t, height, txs, raws)
	raw, cb := candidateFrame(t, parent, 1, raws...)
	final[cb] = btEntry(1, 0, validP2PKCovenantData(), height, true)
	logicalMDBXAssert(t, logicalGrowthCensusBytes(entries) == 801 && logicalGrowthCensusBytes(final) == s1 && len(final)+len(entries) == events,
		"signed growth census %d/%d/%d", logicalGrowthCensusBytes(entries), logicalGrowthCensusBytes(final), len(final)+len(entries))
	candidateAssertGrowthFunding(t, uint64(len(raw)), uint64(events))
	return w, candidateInput(t, raw, parent), canonicalUTXORoot(final), candidateGrowthFunding{parents: entries, spends: raws}
}

func candidateGrowthOutputs(t *testing.T, height uint64, txs []*Tx, raws [][]byte) map[Outpoint]UtxoEntry {
	t.Helper()
	final := map[Outpoint]UtxoEntry{}
	logicalMDBXAssert(t, len(txs) == 9, "growth input count %d", len(txs))
	for i, tx := range txs {
		witness := tx.Witness[0]
		digest, err := SighashV1DigestWithType(tx, 0, 2000, [32]byte{}, 1)
		logicalMDBXAssert(t, err == nil && len(witness.Signature) == 4628 && witness.Signature[4627] == 1, "growth signature envelope %d: %v", i, err)
		ok, err := VerifyMLDSA87Digest32(witness.Pubkey, witness.Signature[:4627], digest)
		logicalMDBXAssert(t, ok && err == nil, "growth signature %d: %v", i, err)
		id := testTxID(t, raws[i])
		for v, output := range tx.Outputs {
			final[Outpoint{Txid: id, Vout: uint32(v)}] = btEntry(output.Value, output.CovenantType, output.CovenantData, height, false)
		}
	}
	return final
}

func candidateW(n, timestamps, caps uint64) uint64 {
	w := n - 149
	b := min(17000000, w, (68000157-n)/3)
	return 16777216 + n + max(131072*min(1024, b/41)+4194304+6*b+w+512*(w/7227), 16*b) + 128*caps + 1024 + 18 + 8*timestamps
}

func candidateAssertGrowthFunding(t *testing.T, n, events uint64) {
	t.Helper()
	w := candidateW(n, 11, 0)
	r, d := 135192+48*events, 288440+104*events
	logicalMDBXAssert(t, n <= 1048576 && w <= 163652311 && w+r <= 164204671 && n+4096+36*events+d <= 2557852,
		"growth funding %d/%d: W=%d, R=%d, D=%d", n, events, w, r, d)
}

func TestCandidateRootGrowth(t *testing.T) {
	t.Run("equal", func(t *testing.T) { candidateGrowthBoundary(t, false) })
	t.Run("over", func(t *testing.T) { candidateGrowthBoundary(t, true) })
	t.Run("cap_first", candidateCapFirst)
	t.Run("inactive_counters", candidateInactiveCounters)
	t.Run("cap_activation", candidateCapActivation)
	t.Run("above_cap_nonincrease", candidateNonincrease)
}

func candidateGrowthBoundary(t *testing.T, over bool) {
	t.Helper()
	w, in, want, funding := candidateGrowthSetup(t, over)
	next, nextRoot := candidateGrowthCoinbase(t, in, funding.parents)
	candidateView(t, w, func(r *mdbx.Reader) {
		if over {
			candidateTxError(t, r, w.owner, in, "BLOCK_ERR_STATE_GROWTH_EXCEEDED", "logical state growth exceeded")
		} else {
			candidateRootOK(t, r, w.owner, in, want)
		}
		candidateRootOK(t, r, w.owner, next, nextRoot)
	})
}

func candidateGrowthCoinbase(t *testing.T, in CandidateRootInput, parents map[Outpoint]UtxoEntry) (CandidateRootInput, [32]byte) {
	t.Helper()
	raw, cb := candidateFrame(t, in.Selection.Parent, 1)
	in.Raw = raw
	final := maps.Clone(parents)
	final[cb] = btEntry(1, 0, validP2PKCovenantData(), in.Selection.Height, true)
	return in, canonicalUTXORoot(final)
}

func candidateSetCap(t *testing.T, in *CandidateRootInput, chain [32]byte, height uint64) {
	t.Helper()
	registry, err := NewCandidateRootCapRegistry([]CandidateRootCapRow{{chain, height}})
	logicalMDBXAssert(t, err == nil, "candidate cap activation: %v", err)
	in.CapRegistry = registry
}

func candidateCapFirst(t *testing.T) {
	w, in, _ := candidateCapFirstInputs(t)
	candidateView(t, w, func(r *mdbx.Reader) {
		candidateTxError(t, r, w.owner, in, "BLOCK_ERR_STATE_CAP_EXCEEDED", "logical state cap exceeded")
	})
}

func candidateCapFirstInputs(t *testing.T) (*btWorld, CandidateRootInput, candidateGrowthFunding) {
	t.Helper()
	w, in, _, funding := candidateGrowthAtHeight(t, true, 20001)
	candidateSetCap(t, &in, [32]byte{}, 20001)
	irCounterV1(t, w, 1649267441664-773120, 25200009)
	return w, in, funding
}

func candidateInactiveCounters(t *testing.T) {
	w, in, _, _ := candidateGrowthSetup(t, true)
	irCounterV1(t, w, 1, 9)
	candidateView(t, w, func(r *mdbx.Reader) {
		got, err := DeriveCandidateUTXORootV1(r, w.owner, in)
		logicalMDBXAssert(t, got == [32]byte{}, "counter refusal returned a digest")
		irFailureV1(t, err, logicalStateFailureStoreIntegrity, "invalid required logical counter envelope")
		id := [32]byte{7}
		candidateReadExact(t, r, 0, []byte{3}, id[:])
	})
}

func candidateCapActivation(t *testing.T) {
	w, in, want, _ := candidateGrowthAtHeight(t, false, 20001)
	candidateSetCap(t, &in, [32]byte{}, 20001)
	for _, s0 := range []uint64{1649267441664 - 773121, 1649267441664 - 773120} {
		irCounterV1(t, w, s0, 25200009)
		candidateView(t, w, func(r *mdbx.Reader) { candidateRootOK(t, r, w.owner, in, want) })
	}
	irCounterV1(t, w, 1649267441664+1, 25200009)
	candidateView(t, w, func(r *mdbx.Reader) {
		for _, at := range []uint64{20000, 20001} {
			candidateSetCap(t, &in, [32]byte{}, at)
			candidateTxError(t, r, w.owner, in, "BLOCK_ERR_STATE_CAP_EXCEEDED", "logical state cap exceeded")
		}
		candidateSetCap(t, &in, [32]byte{}, 20002)
		candidateRootOK(t, r, w.owner, in, want)
		candidateSetCap(t, &in, [32]byte{1}, 20001)
		candidateRootOK(t, r, w.owner, in, want)
	})
}

func candidateNonincrease(t *testing.T) {
	s := newCandidateScene(t, 20001)
	tx := inputViewTx(22, s.funding, s.other)
	tx.Outputs[0] = TxOutput{Value: 2990, CovenantType: 0, CovenantData: s.cov}
	spend := icbSignV1(t, s.key, tx, 1000, 2000)
	raw, cb := candidateFrame(t, s.parent, 1, spend)
	in := candidateInput(t, raw, s.parent)
	candidateSetCap(t, &in, [32]byte{}, 20001)
	irCounterV1(t, s.world, 1649267441664+1, 25200003)
	final := maps.Clone(s.entries)
	delete(final, s.funding)
	delete(final, s.other)
	final[cb] = btEntry(1, 0, validP2PKCovenantData(), 20001, true)
	final[Outpoint{Txid: testTxID(t, spend)}] = btEntry(2990, 0, s.cov, 20001, false)
	candidateView(t, s.world, func(r *mdbx.Reader) { candidateRootOK(t, r, s.world.owner, in, canonicalUTXORoot(final)) })
}

func TestCandidateRootAdmission(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, want := s.body(t, 0, 1)
	t.Run("non_tree_reader", func(t *testing.T) { candidateOrdinaryReader(t, s, in) })
	t.Run("descriptor_suite_registry", candidateDescriptorSuite)
	for _, row := range []struct {
		name string
		edit func(*CandidateRootInput)
		want error
	}{
		{"nil_cap_registry", func(in *CandidateRootInput) { in.CapRegistry = nil }, nil},
		{"zero_cap_registry", func(in *CandidateRootInput) { in.CapRegistry = &CandidateRootCapRegistry{} }, nil},
		{"nil_suite_registry", func(in *CandidateRootInput) { in.Registry = nil }, nil},
		{"zero_suite_registry", func(in *CandidateRootInput) { in.Registry = &SuiteRegistry{} }, nil},
		{"unresolved_suite", func(in *CandidateRootInput) { in.Registry = NewSuiteRegistryFromParams(nil) }, nil},
		{"missing_suite_algorithm", func(in *CandidateRootInput) {
			in.Registry = NewSuiteRegistryFromParams([]SuiteParams{{SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627, VerifyCost: 8, AlgName: ""}})
		}, nil},
		{"missing_inactive_suite_algorithm", func(in *CandidateRootInput) {
			active, _ := in.Registry.Lookup(0x01)
			inactive := active
			inactive.SuiteID, inactive.AlgName = 0x02, ""
			in.Registry = NewSuiteRegistryFromParams([]SuiteParams{active, inactive})
		}, nil},
		{"nil_rotation", func(in *CandidateRootInput) { in.Rotation = nil }, nil},
		{"zero_rotation", func(in *CandidateRootInput) { in.Rotation = &CandidateRootRotation{} }, nil},
		{"different_height", func(in *CandidateRootInput) { in.Rotation = &CandidateRootRotation{rotation: icbFrozenV1(4)} }, nil},
		{"zero_target", func(in *CandidateRootInput) { in.ExpectedTarget = [32]byte{} }, ErrBlockSteps1To12Context},
		{"short_window", func(in *CandidateRootInput) { in.ParentTimestamps = in.ParentTimestamps[:4] }, ErrBlockSteps1To12Context},
		{"long_window", func(in *CandidateRootInput) { in.ParentTimestamps = make([]uint64, 6) }, ErrBlockSteps1To12Context},
		{"oversize_before_window", func(in *CandidateRootInput) { in.Raw, in.ParentTimestamps = make([]byte, 68000158), nil }, ErrInitial148BlockCapacity},
	} {
		t.Run(row.name, func(t *testing.T) {
			bad := in
			row.edit(&bad)
			candidateView(t, s.world, func(r *mdbx.Reader) {
				root, err := DeriveCandidateUTXORootV1(r, s.world.owner, bad)
				logicalMDBXAssert(t, root == [32]byte{}, "invalid context returned digest %x", root)
				if row.want == nil {
					class, cause, ok := InspectCandidateRootFailure(err)
					logicalMDBXAssert(t, ok && class == CandidateRootFailureLocalInvariant && cause != nil && cause.Error() == "invalid candidate validation context",
						"candidate validation class/cause: %v/%v", class, cause)
				} else {
					logicalMDBXAssert(t, any(err) == any(row.want), "candidate admission returned %v, want %v", err, row.want)
				}
				candidateRootOK(t, r, s.world.owner, in, want)
			})
		})
	}
}

func candidateDescriptorSuite(t *testing.T) {
	const height, newSuite = 10, 0x02
	params := []SuiteParams{
		{SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627, VerifyCost: 8, AlgName: "ML-DSA-87"},
		{SuiteID: newSuite, PubkeyLen: 2592, SigLen: 4627, VerifyCost: 8, AlgName: "ML-DSA-87"},
	}
	registry := NewSuiteRegistryFromParams(params)
	descriptor := CryptoRotationDescriptor{
		Name: "test-rotation", OldSuiteID: 0x01, NewSuiteID: newSuite,
		CreateHeight: 1, SpendHeight: 5, SunsetHeight: height,
	}
	err := ValidateRotationDescriptorForNetwork("devnet", descriptor, registry)
	logicalMDBXAssert(t, err == nil, "candidate rotation descriptor: %v", err)
	frozen, err := FreezeCandidateRootRotation(height, DescriptorRotationProvider{Descriptor: descriptor})
	logicalMDBXAssert(t, err == nil, "freeze candidate descriptor: %v", err)

	w, key := btNew(t), icbKeyV1(t)
	cov := p2pkCovenantDataForPubkey(key.PubkeyBytes())
	cov[0] = newSuite
	seed, seedCoinbase, funding := icbSeedV1(t, w, cov, height)
	spend := inputViewTx(11, Outpoint{Txid: funding.id})
	spend.Outputs[0] = TxOutput{Value: 990, CovenantType: COV_TYPE_P2PK, CovenantData: cov}
	spend.Witness[0] = signP2PKInputWitness(t, spend, 0, 1000, [32]byte{}, key)
	spend.Witness[0].SuiteID = newSuite
	signed := icbSignedRawV1(t, spend)
	commit := initial148BlockWitnessCommit(t, signed)
	cb := coinbaseTxWithOutputs(height, []testOutput{
		{value: 1, covenantType: COV_TYPE_P2PK, covenantData: cov},
		{covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
	})
	raw := initial148BlockFrame(t, [][]byte{cb, signed}, func(h *initial148BlockHead) { h.parent = seed.Endpoint.BlockHash })
	in := candidateInput(t, raw, seed.Endpoint)
	in.Registry, in.Rotation = registry, frozen
	want := canonicalUTXORoot(map[Outpoint]UtxoEntry{
		{Txid: seedCoinbase.id}:     btEntry(7, COV_TYPE_P2PK, validP2PKCovenantData(), height-1, true),
		{Txid: funding.id, Vout: 1}: btEntry(2000, COV_TYPE_P2PK, cov, height-1, false),
		{Txid: testTxID(t, signed)}: btEntry(990, COV_TYPE_P2PK, cov, height, false),
		{Txid: testTxID(t, cb)}:     btEntry(1, COV_TYPE_P2PK, cov, height, true),
	})
	candidateView(t, w, func(r *mdbx.Reader) {
		for _, subset := range [][]SuiteParams{params[1:], params[:1]} {
			incomplete := in
			incomplete.Registry = NewSuiteRegistryFromParams(subset)
			root, err := DeriveCandidateUTXORootV1(r, w.owner, incomplete)
			class, cause, ok := InspectCandidateRootFailure(err)
			logicalMDBXAssert(t, root == [32]byte{} && ok && class == CandidateRootFailureLocalInvariant && cause != nil &&
				cause.Error() == "invalid candidate validation context",
				"candidate with only suite %02x: root %x, error %v, class %v, cause %v", subset[0].SuiteID, root, err, class, cause)
			candidateRootOK(t, r, w.owner, in, want)
		}
	})
}

func candidateOrdinaryReader(t *testing.T, s candidateScene, in CandidateRootInput) {
	t.Helper()
	store, err := mdbx.Create(filepath.Join(t.TempDir(), "ordinary"), s.world.cfg)
	logicalMDBXAssert(t, err == nil, "ordinary store: %v", err)
	t.Cleanup(func() { _ = store.Close() })
	err = store.View(func(r *mdbx.Reader) error {
		root, err := DeriveCandidateUTXORootV1(r, s.world.owner, in)
		var engine *mdbx.EngineError
		ok := errors.As(err, &engine)
		logicalMDBXAssert(t, root == [32]byte{} && ok && engine != nil && any(err) == any(engine) && engine.Operation == "get" &&
			engine.Class == "InvalidInput" && engine.Code == 22 && engine.Diagnostic == "tree Reader required",
			"ordinary Reader admission %x/%v", root, err)
		got, found, err := r.Get(mdbx.SchemaV2DBIs()[0], []byte{0})
		logicalMDBXAssert(t, err == nil && found && bytes.Equal(got, []byte{0, 0, 0, 2}), "ordinary Reader after refusal: %x/%t/%v", got, found, err)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "ordinary View after refusal: %v", err)
}

func TestCandidateRootContextConstruction(t *testing.T) {
	for _, rows := range [][]CandidateRootCapRow{
		{{ChainID: [32]byte{1}, ActivationHeight: 1 << 32}},
		{{ChainID: [32]byte{2}}, {ChainID: [32]byte{1}}},
		{{ChainID: [32]byte{1}}, {ChainID: [32]byte{1}}},
	} {
		registry, err := NewCandidateRootCapRegistry(rows)
		logicalMDBXAssert(t, registry == nil && err != nil, "invalid candidate cap rows: %+v/%v", registry, err)
	}
	var missing *candidateFreezeProvider
	frozen, err := FreezeCandidateRootRotation(5, missing)
	logicalMDBXAssert(t, frozen == nil && err != nil, "typed nil rotation: %+v/%v", frozen, err)
	empty, populated := NewNativeSuiteSet(), DefaultRotationProvider{}.NativeCreateSuites(5)
	for _, row := range []struct {
		name          string
		create, spend *NativeSuiteSet
	}{
		{"empty_create", empty, populated},
		{"empty_spend", populated, empty},
	} {
		t.Run(row.name, func(t *testing.T) {
			rotation := &nativeSuiteAvailabilityRotation{create: row.create, spend: row.spend}
			got, err := FreezeCandidateRootRotation(5, rotation)
			logicalMDBXAssert(t, got == nil, "empty suite set returned a frozen context")
			irFailureV1(t, err, logicalStateFailureLocalInvariant, "unresolved candidate suite context")
		})
	}
	t.Run("deployment_read", candidateFrozenDeployment)
	t.Run("copied_cap", candidateCopiedCap)
}

type candidateFreezeProvider struct {
	DefaultRotationProvider
	descriptor []SimplicityDeploymentDescriptor
	calls      int
	err        error
}

func (provider *candidateFreezeProvider) PublishedSimplicityDeployments() ([]SimplicityDeploymentDescriptor, [32]byte, bool, error) {
	provider.calls++
	return provider.descriptor, [32]byte{7}, true, provider.err
}

func candidateFrozenDeployment(t *testing.T) {
	t.Helper()
	cause := errors.New("deployment source unavailable")
	provider := &candidateFreezeProvider{descriptor: []SimplicityDeploymentDescriptor{{ActivationHeight: 5}}, err: cause}
	frozen, err := FreezeCandidateRootRotation(5, provider)
	logicalMDBXAssert(t, err == nil && frozen != nil, "freeze deployment: %v", err)
	provider.descriptor[0].ActivationHeight, provider.err = 6, nil
	deployment := frozen.rotation.(SimplicityDeploymentProvider)
	for range 2 {
		rows, anchor, present, got := deployment.PublishedSimplicityDeployments()
		logicalMDBXAssert(t, len(rows) == 1 && rows[0].ActivationHeight == 5 && anchor == [32]byte{7} && present && any(got) == any(cause),
			"frozen deployment changed: %+v/%x/%t/%v", rows, anchor, present, got)
		rows[0].ActivationHeight = 7
	}
	logicalMDBXAssert(t, provider.calls == 1, "deployment provider read count %d", provider.calls)
}

func candidateCopiedCap(t *testing.T) {
	t.Helper()
	s := newCandidateScene(t, 20001)
	in, want := s.body(t, 0, 1)
	rows := []CandidateRootCapRow{{ChainID: [32]byte{1}, ActivationHeight: 20001}}
	registry, err := NewCandidateRootCapRegistry(rows)
	logicalMDBXAssert(t, err == nil, "ordered cap configuration: %v", err)
	rows[0].ActivationHeight = 20002
	in.CapRegistry, in.ChainID = registry, [32]byte{1}
	irCounterV1(t, s.world, 1649267441664+1, 25200003)
	candidateView(t, s.world, func(r *mdbx.Reader) {
		candidateTxError(t, r, s.world.owner, in, "BLOCK_ERR_STATE_CAP_EXCEEDED", "logical state cap exceeded")
		in.ChainID = [32]byte{2}
		candidateRootOK(t, r, s.world.owner, in, want)
	})
}
