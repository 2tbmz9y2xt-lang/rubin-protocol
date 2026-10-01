//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

var sideWorldConfig = mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}

// sideWorldSpec describes one persisted image: canonical generation 1 heights 0..canonicalTip, selected generation 2
// (F, tip, rows); override[j]=k makes SideLink j name the canonical block at k; custom[j] builds side block j of a
// named body kind; canonicalBody[k] seeds canonical body k ("valid" or "trailing").
type sideWorldSpec struct {
	f, tip        uint64
	rows          uint16
	b             uint64
	canonicalTip  uint64
	pendingSide   bool
	override      map[uint64]uint64
	custom        map[uint64]string
	canonicalBody map[uint64]string
	maxExclusion  bool // authority carries an exclusion slot sized so the encoded authority is exactly MaxMetadataBytes
}

// sideWorld keeps the independently derived expected bytes of every row the operation may read or write; a nil value
// means the row must be absent.
type sideWorld struct {
	t         *testing.T
	path      string
	store     *mdbx.Store
	owner     *mdbx.OperationReservationOwner
	spec      sideWorldSpec
	first     uint64
	authority []byte
	canonical [][32]byte
	entries   map[uint64][]byte
	owners    map[[32]byte][]byte
	links     map[uint64][]byte
	sideAt    map[uint64][32]byte
	headers   map[[32]byte][]byte
	bodies    map[[32]byte][]byte
	exclusion *mdbx.InvalidBranchV1
	// rawEqual, when set by a fixture test, compares committed rows natively (exact bytes or absence, no width
	// bound) so seeded malformed rows are observed; ordinary worlds keep Reader.Get.
	rawEqual func(rank uint8, key, want []byte) (bool, error)
	extra    []sideRawRow // seeded rows outside the tracked maps, compared by wantImage
}

type sideRawRow struct {
	rank       uint8
	key, value []byte
}

// sideWorldBlock is the published genesis body with a new parent and nonce: its stored commitments stay valid and its
// all-FF target has work 1 (RUBIN_L1_CANONICAL.md Section 23 work = floor(2^256/target)).
func sideWorldBlock(parent [32]byte, nonce uint64) []byte {
	block := genesisMDBXHex(genesisMDBXPublishedHex)
	copy(block[4:36], parent[:])
	binary.LittleEndian.PutUint64(block[108:116], nonce)
	return block
}

// sideKindBlock builds a multi-transaction side block whose 116-byte header stays hash-bound while the body carries
// the named stored-commitment defect ("valid" carries none).
func sideKindBlock(t *testing.T, kind string, parent [32]byte, nonce uint64) []byte {
	txs := storedCommitmentsTxs(2, 700)
	all := append([][]byte{coinbaseWithWitnessCommitment(t, txs...)}, txs...)
	block := buildBlockBytes(t, parent, storedCommitmentsRoot(t, all), POW_LIMIT, nonce, all)
	switch kind {
	case "trailing":
		return append(block, 0)
	case "short final":
		return block[:len(block)-1]
	case "zero count":
		return append(append(slices.Clone(block[:BLOCK_HEADER_BYTES]), 0), block[BLOCK_HEADER_BYTES+1:]...)
	case "root":
		return buildBlockBytes(t, parent, [32]byte{0x01}, POW_LIMIT, nonce, all)
	case "coinbase":
		return buildBlockBytes(t, parent, storedCommitmentsRoot(t, txs), POW_LIMIT, nonce, txs)
	case "witness":
		bare := append([][]byte{coinbaseTxWithOutputs(0, []testOutput{{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: make([]byte, 32)}})}, txs...)
		return buildBlockBytes(t, parent, storedCommitmentsRoot(t, bare), POW_LIMIT, nonce, bare)
	}
	return block
}

func sideWorldWork(n uint64) (work [40]byte) {
	binary.BigEndian.PutUint64(work[32:], n)
	return work
}

func newSideWorld(t *testing.T, spec sideWorldSpec) *sideWorld {
	t.Helper()
	w := &sideWorld{
		t: t, path: filepath.Join(t.TempDir(), "db"), spec: spec, first: spec.tip - uint64(spec.rows) + 1, entries: map[uint64][]byte{},
		owners: map[[32]byte][]byte{}, links: map[uint64][]byte{}, sideAt: map[uint64][32]byte{}, headers: map[[32]byte][]byte{}, bodies: map[[32]byte][]byte{},
	}
	var err error
	w.store, err = mdbx.Create(w.path, sideWorldConfig)
	logicalMDBXAssert(t, err == nil, "side world store: %v", err)
	t.Cleanup(func() { _ = w.store.Close() })
	w.owner, err = mdbx.NewOperationReservationOwner(mdbx.MaxOperationDataBytes)
	logicalMDBXAssert(t, err == nil, "side world owner: %v", err)
	truth, _, err := w.store.BootstrapStorageV1(mdbx.StorageProfilePrunedV1, w.owner)
	logicalMDBXAssert(t, err == nil && truth == mdbx.CommitTruthNew, "side world bootstrap: %v/%v", truth, err)
	rows := w.canonicalRows()
	rows = append(rows, w.sideRows()...)
	rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: w.authorityBytes()})
	w.apply(rows...)
	return w
}

// block records one block's expected header and body bytes and returns its header and body literals.
func (w *sideWorld) block(block []byte) (mdbx.Mutation, mdbx.Mutation, [32]byte) {
	hash := sha3_256(block[:BLOCK_HEADER_BYTES])
	w.headers[hash], w.bodies[hash] = block[:BLOCK_HEADER_BYTES], block
	header := mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(hash[:]), AfterKind: mdbx.AfterLiteral, Literal: block[:BLOCK_HEADER_BYTES]}
	body := mdbx.Mutation{DBI: logicalMDBXDBIs[4], Key: bytes.Clone(hash[:]), AfterKind: mdbx.AfterLiteral, Literal: block}
	return header, body, hash
}

func (w *sideWorld) canonicalRows() []mdbx.Mutation {
	var parent [32]byte
	var rows []mdbx.Mutation
	for k := uint64(0); k <= w.spec.canonicalTip; k++ {
		header, body, hash := w.block(sideWorldBlock(parent, k))
		switch w.spec.canonicalBody[k] {
		case "valid":
			rows = append(rows, body)
		case "trailing":
			body.Literal = append(bytes.Clone(body.Literal), 0)
			w.bodies[hash] = body.Literal
			rows = append(rows, body)
		default:
			w.bodies[hash] = nil
		}
		w.entries[k], w.owners[hash] = mdbx.ChainValue(hash, parent, sideWorldWork(k+1)), mdbx.CanonicalOwnerValue(k)
		rows = append(rows, header,
			mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(1, k)), AfterKind: mdbx.AfterLiteral, Literal: w.entries[k]},
			mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, hash)), AfterKind: mdbx.AfterLiteral, Literal: w.owners[hash]})
		w.canonical = append(w.canonical, hash)
		parent = hash
	}
	return rows
}

func (w *sideWorld) sideRows() []mdbx.Mutation {
	parent := w.canonical[w.spec.f]
	start := w.first
	if w.spec.pendingSide {
		start--
	}
	var rows []mdbx.Mutation
	for j := start; j <= w.spec.tip; j++ {
		if k, ok := w.spec.override[j]; ok {
			var prev [32]byte
			if k > 0 {
				prev = w.canonical[k-1]
			}
			rows = append(rows, w.link(j, w.canonical[k], prev, sideWorldWork(j+1)))
			parent = w.canonical[k]
			continue
		}
		block := sideWorldBlock(parent, 1_000_000+j)
		if kind, ok := w.spec.custom[j]; ok {
			block = sideKindBlock(w.t, kind, parent, 1_000_000+j)
		}
		header, body, hash := w.block(block)
		rows = append(rows, w.link(j, hash, parent, sideWorldWork(j+1)), header, body)
		w.sideAt[j] = hash
		parent = hash
	}
	return rows
}

func (w *sideWorld) link(j uint64, hash, parent [32]byte, work [40]byte) mdbx.Mutation {
	value := mdbx.ChainValue(hash, parent, work)
	w.links[j] = value
	return mdbx.Mutation{DBI: logicalMDBXDBIs[6], Key: logicalMDBXMust(mdbx.HeightKey(2, j)), AfterKind: mdbx.AfterLiteral, Literal: value}
}

func (w *sideWorld) promises() (uint64, uint64) {
	if w.spec.b == 0 {
		return 0, 0
	}
	return w.spec.b, w.spec.b + 13_680
}

func (w *sideWorld) authorityBytes() []byte {
	b, u := w.promises()
	a := mdbx.StorageAuthorityV1{
		Version: 1, ActiveProfile: mdbx.StorageProfilePrunedV1, B: b, U: u, ActiveGenerationID: 1, NextGenerationID: 3,
		Phase: mdbx.StoragePhaseNoneV1, Lifecycle: mdbx.StorageLifecycleStableV1,
		SelectedSide: &mdbx.SelectedSideV1{
			GenerationID: 2, F: w.spec.f, TipHeight: w.spec.tip, TipHash: [32]byte(w.links[w.spec.tip][:32]),
			CumulativeChainwork: sideWorldWork(w.spec.tip + 1), RowCount: w.spec.rows, LogicalBytes: uint64(w.spec.rows) * 266,
		},
	}
	if w.spec.pendingSide {
		a.Phase, a.Cleanup = mdbx.StoragePhasePruneGCV1, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 2, FirstHeight: w.first - 1, LastHeight: w.first - 1, NextHeight: w.first - 1}}}
	}
	if w.spec.maxExclusion {
		a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 1, ExactConsensusError: []byte{1}}
		small, err := a.Encode()
		logicalMDBXAssert(w.t, err == nil, "side world exclusion probe: %v", err)
		a.ExcludedInvalidBranch.ExactConsensusError = make([]byte, 1+mdbx.MaxMetadataBytes-len(small))
		w.exclusion = a.ExcludedInvalidBranch
	}
	encoded, err := a.Encode()
	logicalMDBXAssert(w.t, err == nil, "side world authority: %v", err)
	logicalMDBXAssert(w.t, !w.spec.maxExclusion || len(encoded) == mdbx.MaxMetadataBytes, "side world maximal authority is %d bytes", len(encoded))
	w.authority = encoded
	return encoded
}

// clearedAuthority is spelled from the spec: selected cleared, PRUNE_GC/STABLE, one SIDE span over the whole interval,
// or the extended predecessor singleton keeping its progress first-1.
func (w *sideWorld) clearedAuthority() []byte {
	b, u := w.promises()
	span := mdbx.CleanupSpanV1{Kind: mdbx.CleanupSpanSideV1, GenerationID: 2, FirstHeight: w.first, LastHeight: w.spec.tip, NextHeight: w.first}
	if w.spec.pendingSide {
		span.FirstHeight, span.NextHeight = w.first-1, w.first-1
	}
	a := mdbx.StorageAuthorityV1{
		Version: 1, ActiveProfile: mdbx.StorageProfilePrunedV1, B: b, U: u, ActiveGenerationID: 1, NextGenerationID: 3,
		Phase: mdbx.StoragePhasePruneGCV1, Lifecycle: mdbx.StorageLifecycleStableV1, Cleanup: &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{span}}, ExcludedInvalidBranch: w.exclusion,
	}
	encoded, err := a.Encode()
	logicalMDBXAssert(w.t, err == nil, "side world cleared authority: %v", err)
	return encoded
}

func (w *sideWorld) apply(rows ...mdbx.Mutation) {
	w.t.Helper()
	slices.SortFunc(rows, func(a, b mdbx.Mutation) int {
		if a.DBI.Rank != b.DBI.Rank {
			return int(a.DBI.Rank) - int(b.DBI.Rank)
		}
		return bytes.Compare(a.Key, b.Key)
	})
	truth, _, err := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return mdbx.Batch{Mutations: rows}, nil })
	logicalMDBXAssert(w.t, err == nil && truth == mdbx.CommitTruthNew, "side world write: %v/%v", truth, err)
}

func (w *sideWorld) remove(rank uint8, key []byte) {
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[rank], Key: key, BeforePresent: true, AfterKind: mdbx.AfterAbsent})
}

func (w *sideWorld) removeBody(j uint64) {
	hash := w.sideAt[j]
	w.remove(4, bytes.Clone(hash[:]))
	w.bodies[hash] = nil
}

func (w *sideWorld) removeHeader(hash [32]byte) {
	w.remove(3, bytes.Clone(hash[:]))
	w.headers[hash] = nil
}

func (w *sideWorld) removeLink(j uint64) {
	w.remove(6, logicalMDBXMust(mdbx.HeightKey(2, j)))
	w.links[j] = nil
}

func (w *sideWorld) relink(j uint64, parent [32]byte, work [40]byte) {
	m := w.link(j, [32]byte(w.links[j][:32]), parent, work)
	m.BeforePresent = true
	w.apply(m)
}

// reblock replaces side block j by a hash-bound block whose header names headerParent and relinks j to it with
// linkParent and the original work; the replaced rows stay physically present and are no longer tracked.
func (w *sideWorld) reblock(j uint64, headerParent, linkParent [32]byte) {
	header, body, hash := w.block(sideWorldBlock(headerParent, 2_000_000+j))
	link := w.link(j, hash, linkParent, [40]byte(w.links[j][64:104]))
	link.BeforePresent = true
	w.apply(header, body, link)
	w.sideAt[j] = hash
}

// setEntry rewrites canonical entry k in place; every canonical entry literal must be paired with its unchanged
// CanonicalOwnerV1 literal at the same k, so the owner row is rewritten with identical bytes.
func (w *sideWorld) setEntry(k uint64, parent [32]byte, work [40]byte) {
	hash := w.canonical[k]
	w.entries[k] = mdbx.ChainValue(hash, parent, work)
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(1, k)), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: w.entries[k]},
		mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, hash)), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(k)})
}

func (w *sideWorld) removeCanonical(k uint64) {
	hash := w.canonical[k]
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(1, k)), BeforePresent: true, AfterKind: mdbx.AfterAbsent},
		mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: logicalMDBXMust(mdbx.CanonicalOwnerKey(1, hash)), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	w.entries[k], w.owners[hash] = nil, nil
}

func (w *sideWorld) run(h uint64) selectedSideOutcome {
	return selectedSideDamageMDBX(w.store, w.owner, 2, w.spec.tip, h)
}

func (w *sideWorld) reopen() {
	w.t.Helper()
	_ = w.store.Close()
	store, err := mdbx.Open(w.path, sideWorldConfig)
	logicalMDBXAssert(w.t, err == nil, "side world reopen: %v", err)
	w.store = store
}

func (w *sideWorld) wantRow(label string, rank uint8, key, want []byte) {
	w.t.Helper()
	if w.rawEqual != nil {
		equal, err := w.rawEqual(rank, key, want)
		logicalMDBXAssert(w.t, err == nil && equal, "%s: raw rank %d key %x differs (%v)", label, rank, key, err)
		return
	}
	var value []byte
	var present bool
	err := w.store.View(func(reader *mdbx.Reader) error {
		var err error
		value, present, err = reader.Get(logicalMDBXDBIs[rank], key)
		return err
	})
	logicalMDBXAssert(w.t, err == nil && present == (want != nil) && bytes.Equal(value, want), "%s: rank %d key %x present=%v differs (%v)", label, rank, key, present, err)
}

// wantImage compares exact bytes or absence of the authority, every SideLink, every side header/body (leaving headers
// absent after a clear) and every canonical entry, owner row, header and body.
func (w *sideWorld) wantImage(label string, authority []byte, cleared bool) {
	w.t.Helper()
	w.wantRow(label, 0, []byte{2}, authority)
	for j, link := range w.links {
		w.wantRow(label, 6, logicalMDBXMust(mdbx.HeightKey(2, j)), link)
	}
	for j, hash := range w.sideAt {
		header := w.headers[hash]
		if cleared && j >= w.first {
			header = nil
		}
		w.wantRow(label, 3, hash[:], header)
		w.wantRow(label, 4, hash[:], w.bodies[hash])
	}
	for k, hash := range w.canonical {
		w.wantRow(label, 2, logicalMDBXMust(mdbx.HeightKey(1, uint64(k))), w.entries[uint64(k)])
		w.wantRow(label, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(1, hash)), w.owners[hash])
		w.wantRow(label, 3, hash[:], w.headers[hash])
		w.wantRow(label, 4, hash[:], w.bodies[hash])
	}
	for _, row := range w.extra {
		w.wantRow(label, row.rank, row.key, row.value)
	}
}

func (w *sideWorld) wantOpen(label string) {
	w.t.Helper()
	invoked := false
	err := w.store.View(func(*mdbx.Reader) error { invoked = true; return nil })
	logicalMDBXAssert(w.t, err == nil && invoked, "%s: callback-only refusal did not keep the Store open: %v", label, err)
}

func (w *sideWorld) wantConsumed(label string, raw error) {
	w.t.Helper()
	invoked := false
	err := w.store.View(func(*mdbx.Reader) error { invoked = true; return nil })
	logicalMDBXAssert(w.t, err == raw && !invoked, "%s: Store disposition: next View %v, raw %v", label, err, raw) //nolint:errorlint // A consumed Store returns its exact terminal error.
}

func sideWantOutcome(t *testing.T, out selectedSideOutcome, result, canonical string, truth mdbx.CommitTruth, stage mdbx.UpdateStage, label string) {
	t.Helper()
	logicalMDBXAssert(t, out.Result == result && out.CanonicalTruth == canonical && out.Truth == truth && out.Stage == stage, "%s: outcome %+v", label, out)
}

// sideWantReleased proves the operation's full lane is not held: one full grant succeeds, a nested full grant inside
// it is refused with the exact capacity error, and a later grant succeeds again (no residual charge).
func sideWantReleased(t *testing.T, owner *mdbx.OperationReservationOwner, label string) {
	t.Helper()
	err := owner.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		nested := owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { return errors.New("nested full lane granted") })
		logicalMDBXAssert(t, nested != nil && nested.Error() == selectedSideCapacityText, "%s: nested full lane: %v", label, nested)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "%s: full lane still charged: %v", label, err)
	logicalMDBXAssert(t, owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { return nil }) == nil, "%s: residual charge", label)
}

func sideWantEngine(t *testing.T, err error, class mdbx.EngineClass, diagnostic, label string) {
	t.Helper()
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, errors.As(err, &engine) && engine.Class == class && engine.Diagnostic == diagnostic, "%s: error %v", label, err)
}

func sideWantDefect(t *testing.T, out selectedSideOutcome, label string) {
	t.Helper()
	sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, label)
	var failure *selectedSideFailure
	logicalMDBXAssert(t, errors.As(out.Err, &failure), "%s: consensus-detected defect lost: %v", label, out.Err)
}

func sideWantCause(t *testing.T, out selectedSideOutcome, cause, label string) {
	t.Helper()
	sideWantDefect(t, out, label)
	var failure *selectedSideFailure
	logicalMDBXAssert(t, errors.As(out.Err, &failure) && failure.cause.Error() == cause, "%s: cause %v", label, out.Err)
}

var (
	sideFullSpec = sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 1}
	sideCleared  = "LOCAL_STORE_ERROR(noncanonical)"
)

func sideWantCleared(t *testing.T, w *sideWorld, out selectedSideOutcome, label string) {
	t.Helper()
	sideWantOutcome(t, out, sideCleared, "NOT_APPLICABLE", mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed, label)
	logicalMDBXAssert(t, out.Err == nil, "%s: committed clear kept an error: %v", label, out.Err)
	cleared := w.clearedAuthority()
	w.wantImage(label, cleared, true)
	sideWantReleased(t, w.owner, label)
	w.reopen()
	w.wantImage(label+" after reopen", cleared, true)
}

// setDescriptor rewrites only the committed selected descriptor and tracks the exact new authority bytes.
func (w *sideWorld) setDescriptor(edit func(*mdbx.SelectedSideV1)) {
	w.t.Helper()
	a, err := mdbx.DecodeStorageAuthorityV1(w.authority)
	logicalMDBXAssert(w.t, err == nil, "side world authority decode: %v", err)
	edit(a.SelectedSide)
	encoded, err := a.Encode()
	logicalMDBXAssert(w.t, err == nil, "side world authority encode: %v", err)
	w.authority = encoded
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: encoded})
}

// TestSelectedSideDamageAdapterFixture compares admissible committed images through the Reader: a current-tip SideLink
// naming another hash than the descriptor is canonical integrity with no clear, while a lower height keeps its health.
func TestSelectedSideDamageAdapterFixture(t *testing.T) {
	t.Run("H10-hash", func(t *testing.T) {
		w := newSideWorld(t, sideFullSpec)
		w.setDescriptor(func(s *mdbx.SelectedSideV1) { s.TipHash = w.sideAt[3] })
		below := RecheckSelectedSideMDBX(w.store, w.owner, 2, 4, 3)
		sideWantOutcome(t, below, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "below-tip health unchanged")
		logicalMDBXAssert(t, below.Err == nil, "below-tip health kept an error: %v", below.Err)
		sideWantCause(t, RecheckSelectedSideMDBX(w.store, w.owner, 2, 4, 4), "selected side tip link does not name the descriptor tip", "canonical integrity/no clear")
		w.wantImage("tip hash mismatch", w.authority, false)
	})
	t.Run("H10-owner-height", func(t *testing.T) {
		// Side F2 rows 3..4 name canonical k-1 and k (bodies absent); tip link hash/work, owned header and predecessor
		// work agree, so the keyed owner height alone decides: k=2<B=3<=h optional clears; h=4<B=5<=k required defect.
		spec := func(b, k uint64) sideWorldSpec {
			return sideWorldSpec{f: 2, tip: 4, rows: 2, b: b, canonicalTip: 5, override: map[uint64]uint64{3: k - 1, 4: k}}
		}
		w := newSideWorld(t, spec(3, 2))
		sideWantCleared(t, w, RecheckSelectedSideMDBX(w.store, w.owner, 2, 4, 4), "owner k below B at tip h at or above B clears")
		w = newSideWorld(t, spec(5, 5))
		sideWantCause(t, RecheckSelectedSideMDBX(w.store, w.owner, 2, 4, 4), "required canonical row is absent or does not hash to its key", "owner k at or above B at tip h below B integrity")
		w.wantImage("owner k at or above B at tip h below B integrity", w.authority, false)
		w.wantOpen("owner k at or above B at tip h below B integrity")
		sideWantReleased(t, w.owner, "owner k at or above B at tip h below B integrity")
	})
}

// TestSelectedSideDamageAdapter owns the node recheck adapter's bounded current-tip predicates beside the unchanged
// existing health: a tip work disagreement after the owner/header/keep checks is a complete positive-damage clear.
func TestSelectedSideDamageAdapter(t *testing.T) {
	old, pre := mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite
	t.Run("H10-work", func(t *testing.T) {
		w := newSideWorld(t, sideFullSpec)
		w.setDescriptor(func(s *mdbx.SelectedSideV1) { s.CumulativeChainwork = sideWorldWork(9) })
		below := RecheckSelectedSideMDBX(w.store, w.owner, 2, 4, 3)
		sideWantOutcome(t, below, "", "OLD", old, pre, "below-tip health unchanged")
		logicalMDBXAssert(t, below.Err == nil, "below-tip health kept an error: %v", below.Err)
		sideWantCleared(t, w, RecheckSelectedSideMDBX(w.store, w.owner, 2, 4, 4), "persistent tip work mismatch complete damage clear/no healthy retry")
	})
	t.Run("H10-link", func(t *testing.T) {
		w := newSideWorld(t, sideFullSpec)
		w.removeLink(4)
		out := RecheckSelectedSideMDBX(w.store, w.owner, 2, 4, 4)
		sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", old, pre, "missing tip link")
		sideWantEngine(t, out.Err, mdbx.EngineIntegrity, "selected side link is absent", "missing tip link")
	})
	t.Run("plan-clear", func(t *testing.T) {
		// The healthy clear plan: one authority write and three unkept leaving header deletes, no positive damage, no
		// failed read class. A missing required link fails ReadRequiredSideLink itself (recorded Integrity), so the zero plan
		// keeps that failed invocation's branch_data class.
		w := newSideWorld(t, sideFullSpec)
		var plan SelectedSidePlanV1
		var err error
		viewErr := w.store.View(func(reader *mdbx.Reader) error { plan, err = PlanSelectedSideClearMDBX(reader); return nil })
		logicalMDBXAssert(t, viewErr == nil && err == nil && !plan.PositiveDamageClear && plan.ReadResource == "" && len(plan.Batch.Mutations) == 4, "healthy clear plan %+v (%v)", plan, err)
		w.removeLink(3)
		_ = w.store.View(func(reader *mdbx.Reader) error { plan, err = PlanSelectedSideClearMDBX(reader); return nil })
		var engine *mdbx.EngineError
		logicalMDBXAssert(t, errors.As(err, &engine) && engine.Class == mdbx.EngineIntegrity && plan.ReadResource == selectedSideBranch && !plan.PositiveDamageClear && plan.Batch.Mutations == nil && plan.Batch.Consulted == nil, "failed plan %+v (%v)", plan, err)
		// Leaving row 3 names the canonical-owned block 0 whose required header is gone: the required Get succeeds and the
		// owned defect follows, so the zero plan carries no read class.
		w = newSideWorld(t, sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 1, override: map[uint64]uint64{3: 0}})
		w.removeHeader(w.canonical[0])
		_ = w.store.View(func(reader *mdbx.Reader) error { plan, err = PlanSelectedSideClearMDBX(reader); return nil })
		var failure *selectedSideFailure
		logicalMDBXAssert(t, errors.As(err, &failure) && failure.result == selectedSideIntegrity && failure.cause.Error() == "required canonical row is absent or does not hash to its key" &&
			plan.ReadResource == "" && !plan.PositiveDamageClear && plan.Batch.Mutations == nil && plan.Batch.Consulted == nil, "owned defect plan %+v (%v)", plan, err)
		w.wantImage("owned defect plan writes nothing", w.authority, false)
		// A legal authority without a selected side is the exact request refusal before any artifact read.
		w = newSideWorld(t, sideFullSpec)
		a, aerr := mdbx.DecodeStorageAuthorityV1(w.authority)
		a.SelectedSide = nil
		encoded, eerr := a.Encode()
		logicalMDBXAssert(t, aerr == nil && eerr == nil, "side-less authority: %v %v", aerr, eerr)
		w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: encoded})
		viewErr = w.store.View(func(reader *mdbx.Reader) error { plan, err = PlanSelectedSideClearMDBX(reader); return nil })
		logicalMDBXAssert(t, viewErr == nil && err == errSelectedSideRequest && plan.ReadResource == "" && !plan.PositiveDamageClear && plan.Batch.Mutations == nil && plan.Batch.Consulted == nil, "side-less plan %+v (%v, %v)", plan, err, viewErr) //nolint:errorlint // The exact request refusal.
	})
	t.Run("classify", func(t *testing.T) {
		// The exported classifier: a bound finite leaf (qualifier result, or a TxError with its own code) replaces its own
		// occurrence; a mismatched code binds nothing; definitely-precommit maps a non-terminal cause to precommit.
		ioErr, tx, leaf := &mdbx.EngineError{Class: mdbx.EngineIO, Operation: "get", Code: 5}, &TxError{Code: BLOCK_ERR_MERKLE_INVALID}, errors.New("bound")
		for _, c := range []struct {
			err, leaf          error
			stage              mdbx.UpdateStage
			step, result, want string
		}{
			{ioErr, nil, pre, "LOCAL_RESOURCE_UNAVAILABLE(branch_data)", "", "LOCAL_RESOURCE_UNAVAILABLE(branch_data)"},
			{tx, tx, pre, "", "CONSENSUS_INVALID(BLOCK_ERR_MERKLE_INVALID)", "CONSENSUS_INVALID(BLOCK_ERR_MERKLE_INVALID)"},
			{tx, tx, pre, "", "CONSENSUS_INVALID(BLOCK_ERR_PARSE)", "TERMINAL_LOCAL_INVARIANT(evidence)"},
			{leaf, leaf, pre, "", "LOCAL_RESOURCE_UNAVAILABLE(branch_data)", "LOCAL_RESOURCE_UNAVAILABLE(branch_data)"},
			{ioErr, nil, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, "", "", "LOCAL_PERSISTENCE_ERROR(precommit)"},
		} {
			got := ClassifySelectedSideFailureMDBX(c.err, c.stage, c.step, c.leaf, c.result)
			logicalMDBXAssert(t, got == c.want, "classify %v/%q bound %q: %q, want %q", c.err, c.step, c.result, got, c.want)
		}
	})
	t.Run("H10-stale", func(t *testing.T) {
		w := newSideWorld(t, sideFullSpec)
		out := RecheckSelectedSideMDBX(w.store, w.owner, 2, 5, 4)
		sideWantOutcome(t, out, "", "OLD", old, pre, "stale tip recheck")
		logicalMDBXAssert(t, out.Err == errSelectedSideRequest, "stale tip recheck error %v", out.Err) //nolint:errorlint // The exact direct request refusal.
		w.wantImage("stale tip recheck", w.authority, false)
	})
}

func TestSelectedSideDamageHealthyNoOp(t *testing.T) {
	w := newSideWorld(t, sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 1, custom: map[uint64]string{3: "valid"}})
	for _, h := range []uint64{2, 3, 4} {
		out := w.run(h)
		sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, fmt.Sprintf("healthy %d", h))
		logicalMDBXAssert(t, out.Err == nil, "healthy %d kept an error: %v", h, out.Err)
		w.wantImage(fmt.Sprintf("healthy %d", h), w.authority, false)
		w.wantOpen("healthy")
		sideWantReleased(t, w.owner, "healthy")
	}
}

func TestSelectedSideDamageFullClear(t *testing.T) {
	for _, h := range []uint64{2, 3, 4} {
		// Each kind breaks exactly one relation: the header's parent (link parent still the predecessor), the link's
		// parent (header parent still equal to it), or cumulative work.
		for _, damage := range []string{"body absent", "header absent", "header parent mismatch", "link parent mismatch", "work mismatch"} {
			t.Run(fmt.Sprintf("%s at %d", damage, h), func(t *testing.T) {
				w := newSideWorld(t, sideFullSpec)
				switch damage {
				case "body absent":
					w.removeBody(h)
				case "header absent":
					w.removeHeader(w.sideAt[h])
				case "header parent mismatch":
					w.reblock(h, [32]byte{0xdd}, [32]byte(w.links[h][32:64]))
				case "link parent mismatch":
					w.reblock(h, [32]byte{0xee}, [32]byte{0xee})
				case "work mismatch":
					w.relink(h, [32]byte(w.links[h][32:64]), sideWorldWork(h+7))
				}
				if h == w.spec.tip && (damage == "header parent mismatch" || damage == "link parent mismatch") {
					// The reblocked tip row has a new hash: the descriptor names it so the current-tip identity predicate
					// passes and the seeded parent relation stays the diagnosed damage.
					w.setDescriptor(func(s *mdbx.SelectedSideV1) { s.TipHash = w.sideAt[h] })
				}
				sideWantCleared(t, w, w.run(h), damage)
			})
		}
	}
	for _, kind := range []string{"trailing", "short final", "zero count", "root", "coinbase", "witness"} {
		t.Run("body "+kind, func(t *testing.T) {
			w := newSideWorld(t, sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 1, custom: map[uint64]string{3: kind}})
			sideWantCleared(t, w, w.run(3), kind)
		})
	}
}

// TestSelectedSideDamageSameHeightOwner makes the first selected row the canonical block at the same height k=j=2:
// with B<=k the promised body is required (healthy when present and valid, callback-only integrity when absent or
// malformed); with B>k the absent body is optional damage and the owned header is kept by hash.
func TestSelectedSideDamageSameHeightOwner(t *testing.T) {
	spec := func(b uint64, body string) sideWorldSpec {
		s := sideWorldSpec{f: 1, tip: 4, rows: 3, b: b, canonicalTip: 2, override: map[uint64]uint64{2: 2}}
		if body != "" {
			s.canonicalBody = map[uint64]string{2: body}
		}
		return s
	}
	w := newSideWorld(t, spec(1, "valid"))
	out := w.run(2)
	sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "promised body healthy")
	logicalMDBXAssert(t, out.Err == nil, "promised body healthy: %v", out.Err)
	w.wantImage("promised body healthy", w.authority, false)
	for _, row := range []struct {
		b    uint64
		body string
	}{{1, ""}, {1, "trailing"}, {2, ""}} {
		label := fmt.Sprintf("required body B=%d %q", row.b, row.body)
		w = newSideWorld(t, spec(row.b, row.body))
		sideWantDefect(t, w.run(2), label)
		w.wantImage(label, w.authority, false)
		w.wantOpen(label)
		sideWantReleased(t, w.owner, label)
	}
	// A healthy promised body with a changed entry parent (same hash and work) is the owned header's canonical defect.
	w = newSideWorld(t, spec(1, "valid"))
	w.setEntry(2, [32]byte{0xbb}, sideWorldWork(3))
	sideWantCause(t, w.run(2), "kept canonical header does not link to its index entry", "owned header entry parent")
	w.wantOpen("owned header entry parent")
	w.wantImage("owned header entry parent", w.authority, false)
	sideWantReleased(t, w.owner, "owned header entry parent")
	// Checked h=k=3 owned: a corrupt entry parent wins before the also-wrong SideLink parent and the absent SideLink 2
	// are diagnosed; with only the SideLink parent wrong the row is optional damage and the owned header is kept.
	mixed := sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 3, override: map[uint64]uint64{2: 2, 3: 3}, canonicalBody: map[uint64]string{3: "valid"}}
	w = newSideWorld(t, mixed)
	w.setEntry(3, [32]byte{0xbb}, sideWorldWork(4))
	w.relink(3, [32]byte{0xcc}, sideWorldWork(4))
	w.removeLink(2)
	sideWantCause(t, w.run(3), "kept canonical header does not link to its index entry", "owned entry parent before optional diagnosis")
	w.wantOpen("owned entry parent before optional diagnosis")
	w.wantImage("owned entry parent before optional diagnosis", w.authority, false)
	sideWantReleased(t, w.owner, "owned entry parent before optional diagnosis")
	w = newSideWorld(t, mixed)
	w.relink(3, [32]byte{0xcc}, sideWorldWork(4))
	sideWantCleared(t, w, w.run(3), "wrong SideLink parent keeps owned header")
	w = newSideWorld(t, spec(3, ""))
	sideWantCleared(t, w, w.run(2), "optional body below B")
}

// TestSelectedSideDamageHashKeyedOwners uses one-slot worlds (C=1440, rows 1439, pending SIDE(2,5,5,5)) whose first
// SideLink names a canonical block at k on the other side of B from the reference height h=6: the body is required
// exactly iff k>=B, and every kept header is kept by hash at k, not by j.
func TestSelectedSideDamageHashKeyedOwners(t *testing.T) {
	t.Run("k below B at h at or above B clears", func(t *testing.T) {
		// Maximal legal shape for the transfer budget: one-slot 1439 rows, a 1 MiB authority, a duplicate kept hash (100
		// and 300 both name canonical 7) that reuses its one owner and header observation.
		w := newSideWorld(t, sideWorldSpec{f: 4, tip: 1444, rows: 1439, b: 5, canonicalTip: 8, pendingSide: true, maxExclusion: true, override: map[uint64]uint64{6: 1, 100: 7, 200: 3, 300: 7}})
		sideWantCleared(t, w, w.run(6), "k below B")
	})
	t.Run("k at or above B at h below B is canonical integrity", func(t *testing.T) {
		w := newSideWorld(t, sideWorldSpec{f: 4, tip: 1444, rows: 1439, b: 7, canonicalTip: 8, pendingSide: true, override: map[uint64]uint64{6: 8}})
		sideWantDefect(t, w.run(6), "k above B")
		w.wantImage("k above B", w.authority, false)
		w.wantOpen("k above B")
		sideWantReleased(t, w.owner, "k above B")
	})
	oneSlot := sideWorldSpec{f: 4, tip: 1444, rows: 1439, b: 5, canonicalTip: 8, pendingSide: true}
	for _, h := range []uint64{700, 1444} {
		t.Run(fmt.Sprintf("one-slot optional damage at %d", h), func(t *testing.T) {
			w := newSideWorld(t, oneSlot)
			w.removeBody(h)
			sideWantCleared(t, w, w.run(h), "one-slot damage")
		})
	}
	// R1: the body of the pending SIDE row below the one-slot interval is outside the descriptor, so its absence is not
	// selected-side damage and the first retained row stays healthy.
	t.Run("missing oldest outside one-slot is not damage", func(t *testing.T) {
		w := newSideWorld(t, oneSlot)
		w.removeBody(5)
		out := w.run(6)
		sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "missing oldest outside")
		logicalMDBXAssert(t, out.Err == nil, "missing oldest outside: %v", out.Err)
		w.wantImage("missing oldest outside", w.authority, false)
	})
}

// TestSelectedSideDamageRequiredCanonicalEvidence finds positive damage at h=2 and then meets a defect in the kept
// canonical header of leaving row 3 (named canonical block 0), or in the canonical anchor F=1 at h=2 itself. Each
// consensus-detected defect is callback-only integrity with the OLD image and an open Store; a legal anchor work of
// exactly 2^288 stays inside the domain and only fails the selected predecessor work comparison.
func TestSelectedSideDamageRequiredCanonicalEvidence(t *testing.T) {
	kept := sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 1, override: map[uint64]uint64{3: 0}}
	for _, row := range []struct {
		name    string
		spec    sideWorldSpec
		prepare func(*sideWorld)
	}{
		{"kept header absent", kept, func(w *sideWorld) { w.removeBody(2); w.removeHeader(w.canonical[0]) }},
		{"kept header parent differs from entry", kept, func(w *sideWorld) { w.removeBody(2); w.setEntry(0, [32]byte{0xbb}, sideWorldWork(1)) }},
		{"anchor absent", sideFullSpec, func(w *sideWorld) { w.removeCanonical(1) }},
		{"anchor zero work", sideFullSpec, func(w *sideWorld) { w.setEntry(1, w.canonical[0], [40]byte{}) }},
		{"anchor work above 2^288", sideFullSpec, func(w *sideWorld) { w.setEntry(1, w.canonical[0], [40]byte{3: 1, 39: 1}) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newSideWorld(t, row.spec)
			row.prepare(w)
			sideWantDefect(t, w.run(2), row.name)
			w.wantImage(row.name, w.authority, false)
			w.wantOpen(row.name)
			sideWantReleased(t, w.owner, row.name)
		})
	}
	w := newSideWorld(t, sideFullSpec)
	w.setEntry(1, w.canonical[0], [40]byte{3: 1})
	sideWantCleared(t, w, w.run(2), "anchor work exactly 2^288")
}

func TestSelectedSideDamageUnknownIdentity(t *testing.T) {
	for _, row := range []struct {
		name, diagnostic string
		damage, link     uint64
		work             *[40]byte // nil removes the link; otherwise a legal-width link with this chainwork
	}{
		{"later leaving link", "selected side link is absent", 2, 4, nil},
		{"checked link", "selected side link is absent", 3, 3, nil},
		{"later link zero work", "selected side link identity is undecodable", 2, 4, &[40]byte{}},
		{"checked link work above 2^288", "selected side link identity is undecodable", 3, 3, &[40]byte{3: 1, 39: 1}},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newSideWorld(t, sideFullSpec)
			w.removeBody(row.damage)
			if row.work == nil {
				w.removeLink(row.link)
			} else {
				w.relink(row.link, [32]byte(w.links[row.link][32:64]), *row.work)
			}
			out := w.run(row.damage)
			sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, row.name)
			sideWantEngine(t, out.Err, mdbx.EngineIntegrity, row.diagnostic, row.name)
			w.wantConsumed(row.name, out.Err)
			sideWantReleased(t, w.owner, row.name)
			w.reopen()
			w.wantImage(row.name, w.authority, false)
		})
	}
}

func TestSelectedSideDamageRequestAndVerification(t *testing.T) {
	w := newSideWorld(t, sideFullSpec)
	w.removeBody(3)
	for _, request := range []struct {
		name      string
		g, tip, h uint64
	}{{"generation", 3, 4, 3}, {"tip", 2, 5, 3}, {"below first", 2, 4, 1}, {"above tip", 2, 4, 5}} {
		out := selectedSideDamageMDBX(w.store, w.owner, request.g, request.tip, request.h)
		sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, request.name)
		logicalMDBXAssert(t, out.Err == errSelectedSideRequest, "%s: request refusal identity: %v", request.name, out.Err) //nolint:errorlint // Exact direct refusal.
		w.wantImage(request.name, w.authority, false)
		w.wantOpen(request.name)
	}
	w.reopen()
	out := w.run(3)
	sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "unverified Open")
	sideWantEngine(t, out.Err, mdbx.EngineInvalidInput, "canonical owner index is not verified", "unverified Open")
	w.wantImage("unverified Open", w.authority, false)
	w.wantOpen("unverified Open")
	sideWantReleased(t, w.owner, "unverified Open")
}

func TestSelectedSideDamageReservationComposition(t *testing.T) {
	w := newSideWorld(t, sideFullSpec)
	w.removeBody(3)
	for _, owner := range []*mdbx.OperationReservationOwner{nil, {}} {
		out := selectedSideDamageMDBX(w.store, owner, 2, 4, 3)
		sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "invalid owner")
		logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "invalid storage operation reservation input", "invalid owner: %v", out.Err)
		w.wantImage("invalid owner ran no Update", w.authority, false)
	}
	// A valid owner with a nil Store returns Store.Update's own nil-receiver refusal (mdbx_cgo.go Update: InvalidInput,
	// operation "update", MDBX_EINVAL 22, "nil Store") unchanged as the empty-result API refusal.
	out := selectedSideDamageMDBX(nil, w.owner, 2, 4, 3)
	sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "nil Store")
	nilStore, direct := out.Err.(*mdbx.EngineError) //nolint:errorlint // The raw Store.Update refusal itself is the contract, not a wrapped cause.
	logicalMDBXAssert(t, direct && nilStore != nil && nilStore.Class == mdbx.EngineInvalidInput && nilStore.Operation == "update" && nilStore.Code == 22 && nilStore.Diagnostic == "nil Store" && nilStore.Cause == nil, "nil Store: %v", out.Err)
	sideWantReleased(t, w.owner, "nil Store")
	w.wantImage("nil Store", w.authority, false)
	denied := func(g uint64) selectedSideOutcome {
		var out selectedSideOutcome
		err := w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { out = selectedSideDamageMDBX(w.store, w.owner, g, 4, 3); return nil })
		logicalMDBXAssert(t, err == nil, "outer charge: %v", err)
		return out
	}
	out = denied(2)
	sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "denied")
	logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == selectedSideCapacityText, "denied: %v", out.Err)
	w.wantImage("denied", w.authority, false)
	w.wantOpen("denied")
	w.removeLink(3)
	out = denied(2)
	sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "denied reads no artifact")
	w.wantImage("denied reads no artifact", w.authority, false)
	w.wantOpen("denied reads no artifact")
	out = denied(3)
	sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "denied request")
	logicalMDBXAssert(t, out.Err == errSelectedSideRequest, "denied request: control qualification lost to capacity: %v", out.Err) //nolint:errorlint // Exact direct refusal.
	w.wantOpen("denied request")
	for _, nested := range []bool{false, true} {
		var busy selectedSideOutcome
		view := func() error {
			return w.store.View(func(*mdbx.Reader) error { busy = w.run(3); return nil })
		}
		var err error
		if nested {
			err = w.owner.WithReservation(mdbx.MaxOperationDataBytes, view)
		} else {
			err = view()
		}
		logicalMDBXAssert(t, err == nil, "busy holder: %v", err)
		sideWantOutcome(t, busy, "LOCAL_RESOURCE_UNAVAILABLE(storage_concurrency)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "busy")
		sideWantEngine(t, busy.Err, mdbx.EngineConcurrency, "store operation in progress", "busy")
		w.wantImage("busy", w.authority, false)
		w.wantOpen("busy")
	}
	sideWantReleased(t, w.owner, "composition")
}

// TestSelectedSideDamageProjection pins the raw-to-logical projection over literal tuples; the composed native
// outcomes are proved separately through the fixture-only native bridge on real persisted images.
func TestSelectedSideDamageProjection(t *testing.T) {
	healthy := errors.New("healthy")
	io, transaction, integrity := &mdbx.EngineError{Class: mdbx.EngineIO}, &mdbx.EngineError{Class: mdbx.EngineTransaction}, &mdbx.EngineError{Class: mdbx.EngineIntegrity}
	crossed := &mdbx.CommitError{Cause: io, Truth: mdbx.CommitTruthUnknown}
	prewrite := func(err error) selectedSideOutcome {
		return selectedSideOutcome{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite, Err: err}
	}
	for _, row := range []struct {
		name, step, result, canonical string
		in                            selectedSideOutcome
		normalized                    bool
	}{
		{name: "crossed NEW", in: selectedSideOutcome{Truth: mdbx.CommitTruthNew, Stage: mdbx.UpdateStageCommitMayHaveCrossed}, result: sideCleared, canonical: "NOT_APPLICABLE"},
		{name: "crossed UNKNOWN", in: selectedSideOutcome{Truth: mdbx.CommitTruthUnknown, Stage: mdbx.UpdateStageCommitMayHaveCrossed, Err: crossed}, result: sideCleared, canonical: "NOT_APPLICABLE"},
		{name: "precommit native", in: selectedSideOutcome{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStageWriteStartedDefinitelyPrecommit, Err: io}, result: "LOCAL_PERSISTENCE_ERROR(precommit)", canonical: "OLD"},
		{name: "precommit integrity", in: selectedSideOutcome{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStageWriteStartedDefinitelyPrecommit, Err: integrity}, result: "TERMINAL_STORE_INTEGRITY(canonical)", canonical: "OLD"},
		{name: "healthy sentinel", in: prewrite(healthy), step: selectedSideBranch, canonical: "OLD", normalized: true},
		{name: "wrapped healthy", in: prewrite(fmt.Errorf("wrapped: %w", healthy)), result: "TERMINAL_LOCAL_INVARIANT(evidence)", canonical: "OLD"},
		{name: "optional read", in: prewrite(io), step: selectedSideBranch, result: "LOCAL_RESOURCE_UNAVAILABLE(branch_data)", canonical: "OLD"},
		{name: "required read", in: prewrite(transaction), step: selectedSideCanonical, result: "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)", canonical: "OLD"},
		{name: "capacity then abort", in: prewrite(errors.Join(&selectedSideFailure{result: selectedSideCapacity, cause: io}, transaction)), step: selectedSideBranch, result: "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", canonical: "OLD"},
		{name: "request refusal", in: prewrite(errSelectedSideRequest), step: selectedSideCanonical, canonical: "OLD"},
	} {
		row.in.CanonicalTruth = "OLD"
		got := selectedSideDamageProject(row.in, &selectedSideDamagePlan{healthy: healthy, step: row.step})
		want := row.in.Err
		if row.normalized {
			want = nil
		}
		logicalMDBXAssert(t, got.Result == row.result && got.CanonicalTruth == row.canonical, "%s: projection %+v", row.name, got)
		logicalMDBXAssert(t, got.Truth == row.in.Truth && got.Stage == row.in.Stage && got.Err == want, "%s: raw tuple changed: %+v", row.name, got) //nolint:errorlint // Raw error identity is preserved.
	}
}
