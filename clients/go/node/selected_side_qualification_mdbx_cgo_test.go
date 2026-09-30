//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

var (
	ssqConfig = mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}
	ssqDBIs   = mdbx.SchemaV2DBIs()
)

// ssqCommitment is the witness commitment of every one-transaction block: a zero coinbase wtxid.
var ssqCommitment = func() [32]byte {
	root, err := consensus.WitnessMerkleRootWtxids([][32]byte{{}})
	if err != nil {
		panic(err)
	}
	return consensus.WitnessCommitmentHash(root)
}()

// Literal result classes, spelled independently of the production constants.
const (
	ssqIntegrity = "TERMINAL_STORE_INTEGRITY(canonical)"
	ssqBranch    = "LOCAL_RESOURCE_UNAVAILABLE(branch_data)"
	ssqCanonical = "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"
	ssqRecovery  = "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)"
	ssqRequired  = "RECOVERY_REQUIRED"
)

// ssqSpec is one committed image: canonical generation-1 headers at heights [from, tip] with paired forward/owner rows
// at [owned, tip], and an optional generation-2 selected side.
type ssqSpec struct {
	from, owned, tip uint64
	b                uint64
	work             func(uint64) [40]byte
	side             *ssqSideSpec
	authority        func(*mdbx.StorageAuthorityV1)
}

// ssqSideSpec stores side headers (from default f+1) through tip, the tip SideLink and, unless noBody, the tip body;
// a bare tip body is hash-bound and root-valid but carries no witness commitment output.
type ssqSideSpec struct {
	f, tip, from, work     uint64
	rows                   uint16
	noBody, coinbase, bare bool
}

// ssqBareTx is the minimal 21-byte kind-0 transaction with no inputs, outputs or witness.
var ssqBareTx = consensus.AppendCompactSize(consensus.AppendCompactSize(consensus.AppendU32le(consensus.AppendCompactSize(consensus.AppendCompactSize(consensus.AppendU64le(append(consensus.AppendU32le(nil, 1), 0x00), 0), 0), 0), 0), 0), 0)

type ssqRow struct {
	rank       uint8
	key, value []byte
}

// ssqWorld tracks the independently derived expected bytes of every committed row it wrote.
type ssqWorld struct {
	t         *testing.T
	path      string
	store     *mdbx.Store
	owner     *mdbx.OperationReservationOwner
	spec      ssqSpec
	canonical map[uint64][32]byte
	side      map[uint64][32]byte
	headers   map[[32]byte][]byte
	rows      map[string]ssqRow
	absent    [][32]byte
	rawEqual  func(rank uint8, key, want []byte) (bool, error)
}

func ssqMust(key []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return key
}

func ssqTime(k uint64) uint64 { return 1_000_000 + 120*k }

func ssqWork(n uint64) (work [40]byte) {
	binary.BigEndian.PutUint64(work[32:], n)
	return work
}

func ssqHeader(prev, root [32]byte, timestamp uint64, target [32]byte, nonce uint64) []byte {
	h := append(consensus.AppendU32le(nil, 1), prev[:]...)
	h = consensus.AppendU64le(append(h, root[:]...), timestamp)
	return consensus.AppendU64le(append(h, target[:]...), nonce)
}

func ssqHash(block []byte) [32]byte {
	hash, err := consensus.BlockHash(block[:consensus.BLOCK_HEADER_BYTES])
	if err != nil {
		panic(err)
	}
	return hash
}

// ssqTx is a one-output transaction carrying ssqCommitment; without coinbase it has no input (step-13 invalid).
func ssqTx(coinbase bool) []byte {
	b := consensus.AppendU64le(append(consensus.AppendU32le(nil, 1), 0x00), 0)
	if coinbase {
		b = consensus.AppendU32le(append(consensus.AppendCompactSize(b, 1), make([]byte, 32)...), math.MaxUint32)
		b = consensus.AppendU32le(consensus.AppendCompactSize(b, 0), math.MaxUint32)
	} else {
		b = consensus.AppendCompactSize(b, 0)
	}
	b = consensus.AppendU16le(consensus.AppendU64le(consensus.AppendCompactSize(b, 1), 0), consensus.COV_TYPE_ANCHOR)
	b = append(consensus.AppendCompactSize(b, 32), ssqCommitment[:]...)
	return consensus.AppendCompactSize(consensus.AppendCompactSize(consensus.AppendU32le(b, 0), 0), 0)
}

func ssqBlock(t *testing.T, prev [32]byte, timestamp uint64, target [32]byte, nonce uint64, coinbase bool) []byte {
	t.Helper()
	return ssqBlockOf(t, prev, timestamp, target, nonce, ssqTx(coinbase))
}

// ssqBlockOf is a one-transaction block whose header commits to tx's txid.
func ssqBlockOf(t *testing.T, prev [32]byte, timestamp uint64, target [32]byte, nonce uint64, tx []byte) []byte {
	t.Helper()
	_, txid, _, _, err := consensus.ParseTx(tx)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	root, err := consensus.MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	return append(consensus.AppendCompactSize(ssqHeader(prev, root, timestamp, target, nonce), 1), tx...)
}

// ssqMine returns the first coinbase block whose header satisfies target and accept.
func ssqMine(t *testing.T, prev [32]byte, timestamp uint64, target [32]byte, accept func([32]byte) bool) []byte {
	t.Helper()
	for nonce := uint64(0); nonce < 1<<20; nonce++ {
		block := ssqBlock(t, prev, timestamp, target, nonce, true)
		if consensus.PowCheck(block[:consensus.BLOCK_HEADER_BYTES], target) == nil && (accept == nil || accept(ssqHash(block))) {
			return block
		}
	}
	t.Fatal("no nonce satisfies the candidate target")
	return nil
}

func newSSQWorld(t *testing.T, spec ssqSpec) *ssqWorld {
	t.Helper()
	if spec.work == nil {
		spec.work = func(k uint64) [40]byte { return ssqWork(k + 1) }
	}
	if spec.side != nil && spec.side.work == 0 {
		spec.side.work = spec.side.tip + 1
	}
	w := &ssqWorld{
		t: t, path: filepath.Join(t.TempDir(), "db"), spec: spec, canonical: map[uint64][32]byte{}, side: map[uint64][32]byte{},
		headers: map[[32]byte][]byte{}, rows: map[string]ssqRow{},
	}
	var err error
	w.store, err = mdbx.Create(w.path, ssqConfig)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = w.store.Close() })
	w.owner, err = mdbx.NewOperationReservationOwner(mdbx.MaxOperationDataBytes)
	if err != nil {
		t.Fatalf("reservation owner: %v", err)
	}
	truth, _, err := w.store.BootstrapStorageV1(mdbx.StorageProfilePrunedV1, w.owner)
	if err != nil || truth != mdbx.CommitTruthNew {
		t.Fatalf("bootstrap: %v/%v", truth, err)
	}
	groups := w.canonicalGroups()
	groups = append(groups, w.sideGroups()...)
	// One legal undo manifest (schema.go validateUndoValue: 33 bytes, tag 1) and the replaced logical counter row
	// (bootstrap_cgo.go already creates meta 0x10/1, hence BeforePresent) make those images observable.
	var undoHash [32]byte
	binary.BigEndian.PutUint64(undoHash[:], 0x756e646f)
	groups = append(groups, []mdbx.Mutation{
		w.authorityMutation(w.authorityValue()),
		w.literal(0, ssqMust(mdbx.MetaKey(0x10, 1)), mdbx.LogicalCounterValue(7, 3), true),
		w.literal(5, mdbx.UndoManifestKey(undoHash), mdbx.UndoManifestValue(1, [16]byte{}, 1, 0), false),
	})
	w.apply(groups...)
	return w
}

func (w *ssqWorld) literal(rank uint8, key, value []byte, before bool) mdbx.Mutation {
	w.rows[string(append([]byte{rank}, key...))] = ssqRow{rank: rank, key: key, value: value}
	return mdbx.Mutation{DBI: ssqDBIs[rank], Key: key, BeforePresent: before, AfterKind: mdbx.AfterLiteral, Literal: value}
}

func (w *ssqWorld) absentRow(rank uint8, key []byte) mdbx.Mutation {
	delete(w.rows, string(append([]byte{rank}, key...)))
	return mdbx.Mutation{DBI: ssqDBIs[rank], Key: key, BeforePresent: true, AfterKind: mdbx.AfterAbsent}
}

// canonicalGroups keeps each height's header, forward and owner rows in one group so pairing holds per batch.
func (w *ssqWorld) canonicalGroups() [][]mdbx.Mutation {
	prev := [32]byte{0xee}
	var groups [][]mdbx.Mutation
	for k := w.spec.from; k <= w.spec.tip; k++ {
		header := ssqHeader(prev, [32]byte{}, ssqTime(k), consensus.POW_LIMIT, k)
		hash := ssqHash(header)
		w.canonical[k], w.headers[hash] = hash, header
		group := []mdbx.Mutation{w.literal(3, bytes.Clone(hash[:]), header, false)}
		if k >= w.spec.owned {
			group = append(group, w.literal(2, ssqMust(mdbx.HeightKey(1, k)), mdbx.ChainValue(hash, prev, w.spec.work(k)), false),
				w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, hash)), mdbx.CanonicalOwnerValue(k), false))
		}
		groups = append(groups, group)
		prev = hash
	}
	return groups
}

func (w *ssqWorld) sideGroups() [][]mdbx.Mutation {
	s := w.spec.side
	if s == nil {
		return nil
	}
	from, prev := s.from, [32]byte{0xdd}
	if from == 0 {
		from = s.f + 1
	}
	if from == s.f+1 {
		prev = w.canonical[s.f]
	}
	var groups [][]mdbx.Mutation
	for j := from; j < s.tip; j++ {
		header := ssqHeader(prev, [32]byte{}, ssqTime(j)-7, consensus.POW_LIMIT, 1_000_000+j)
		hash := ssqHash(header)
		w.side[j], w.headers[hash] = hash, header
		groups = append(groups, []mdbx.Mutation{w.literal(3, bytes.Clone(hash[:]), header, false)})
		prev = hash
	}
	tx := ssqTx(s.coinbase)
	if s.bare {
		tx = ssqBareTx
	}
	block := ssqBlockOf(w.t, prev, ssqTime(s.tip)-7, consensus.POW_LIMIT, 1_000_000+s.tip, tx)
	hash := ssqHash(block)
	w.side[s.tip], w.headers[hash] = hash, block[:consensus.BLOCK_HEADER_BYTES]
	groups = append(groups, []mdbx.Mutation{
		w.literal(3, bytes.Clone(hash[:]), block[:consensus.BLOCK_HEADER_BYTES], false),
		w.literal(6, ssqMust(mdbx.HeightKey(2, s.tip)), mdbx.ChainValue(hash, prev, ssqWork(s.work)), false),
	})
	if !s.noBody {
		groups = append(groups, []mdbx.Mutation{w.literal(4, bytes.Clone(hash[:]), block, false)})
	}
	return groups
}

func (w *ssqWorld) authorityValue() mdbx.StorageAuthorityV1 {
	a := mdbx.StorageAuthorityV1{
		Version: 1, ActiveProfile: mdbx.StorageProfilePrunedV1, B: w.spec.b, ActiveGenerationID: 1, NextGenerationID: 3,
		Phase: mdbx.StoragePhaseNoneV1, Lifecycle: mdbx.StorageLifecycleStableV1,
	}
	if a.B > 0 {
		a.U = a.B + 13_680
	}
	if s := w.spec.side; s != nil {
		a.SelectedSide = &mdbx.SelectedSideV1{
			GenerationID: 2, F: s.f, TipHeight: s.tip, TipHash: w.side[s.tip], CumulativeChainwork: ssqWork(s.work), RowCount: s.rows, LogicalBytes: uint64(s.rows) * 1_000,
		}
	}
	if w.spec.authority != nil {
		w.spec.authority(&a)
	}
	return a
}

func (w *ssqWorld) authorityMutation(a mdbx.StorageAuthorityV1) mdbx.Mutation {
	encoded, err := a.Encode()
	if err != nil {
		w.t.Fatalf("authority encode: %v", err)
	}
	return w.literal(0, []byte{2}, encoded, true)
}

// apply commits the groups in sorted batches of at most about 3000 rows through the public Update.
func (w *ssqWorld) apply(groups ...[]mdbx.Mutation) {
	w.t.Helper()
	var batch []mdbx.Mutation
	flush := func() {
		if len(batch) == 0 {
			return
		}
		rows := batch
		slices.SortFunc(rows, func(a, b mdbx.Mutation) int { return cmp.Or(cmp.Compare(a.DBI.Rank, b.DBI.Rank), bytes.Compare(a.Key, b.Key)) })
		truth, _, err := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return mdbx.Batch{Mutations: rows}, nil })
		if err != nil || truth != mdbx.CommitTruthNew {
			w.t.Fatalf("setup write: %v/%v", truth, err)
		}
		batch = nil
	}
	for _, group := range groups {
		if len(batch)+len(group) > 3_000 {
			flush()
		}
		batch = append(batch, group...)
	}
	flush()
}

// relink rewrites the tip SideLink; the authority descriptor is unchanged.
func (w *ssqWorld) relink(hash, prev [32]byte, work uint64) {
	w.apply([]mdbx.Mutation{w.literal(6, ssqMust(mdbx.HeightKey(2, w.spec.side.tip)), mdbx.ChainValue(hash, prev, ssqWork(work)), true)})
}

// setEntry rewrites canonical entry k with its unchanged paired owner literal.
func (w *ssqWorld) setEntry(k uint64, prev [32]byte) {
	hash := w.canonical[k]
	w.apply([]mdbx.Mutation{
		w.literal(2, ssqMust(mdbx.HeightKey(1, k)), mdbx.ChainValue(hash, prev, w.spec.work(k)), true),
		w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, hash)), mdbx.CanonicalOwnerValue(k), true),
	})
}

func (w *ssqWorld) reopen() {
	w.t.Helper()
	_ = w.store.Close()
	store, err := mdbx.Open(w.path, ssqConfig)
	if err != nil {
		w.t.Fatalf("reopen: %v", err)
	}
	w.store = store
}

// wantImage proves every tracked row and every candidate's absence; a consumed handle is reopened first.
func (w *ssqWorld) wantImage(label string) {
	w.t.Helper()
	if w.store.View(func(*mdbx.Reader) error { return nil }) != nil {
		w.reopen()
	}
	check := w.rawEqual
	if check == nil {
		check = w.viewEqual
	}
	for _, row := range w.rows {
		if equal, err := check(row.rank, row.key, row.value); err != nil || !equal {
			w.t.Fatalf("%s: row %d/%x changed (%v)", label, row.rank, row.key, err)
		}
	}
	for _, hash := range w.absent {
		for _, rank := range []uint8{3, 4} {
			if equal, err := check(rank, bytes.Clone(hash[:]), nil); err != nil || !equal {
				w.t.Fatalf("%s: candidate row %d present (%v)", label, rank, err)
			}
		}
	}
}

func (w *ssqWorld) viewEqual(rank uint8, key, want []byte) (bool, error) {
	var equal bool
	err := w.store.View(func(r *mdbx.Reader) error {
		value, present, err := r.Get(ssqDBIs[rank], key)
		equal = present == (want != nil) && bytes.Equal(value, want)
		return err
	})
	return equal, err
}

// run qualifies raw in a View and proves the committed image unchanged.
func (w *ssqWorld) run(raw []byte) (selectedSideQualification, error) {
	w.t.Helper()
	defer w.wantRaw(raw, bytes.Clone(raw))
	var got selectedSideQualification
	err := w.store.View(func(r *mdbx.Reader) error {
		var qerr error
		got, qerr = qualifySelectedSideMDBX(r, raw)
		return qerr
	})
	w.wantImage("after qualification")
	return got, err
}

// wantRaw proves the caller's raw bytes unchanged by the invocation.
func (w *ssqWorld) wantRaw(raw, before []byte) {
	w.t.Helper()
	if !bytes.Equal(raw, before) {
		w.t.Fatal("qualification changed the caller's raw bytes")
	}
}

// timestamps walks the tracked headers newest-first from parent.
func (w *ssqWorld) timestamps(parent [32]byte, count int) []uint64 {
	times := make([]uint64, 0, count)
	for hash := parent; len(times) < count; {
		header, ok := w.headers[hash]
		if !ok {
			w.t.Fatalf("no tracked header %x for the window", hash)
		}
		times = append(times, binary.LittleEndian.Uint64(header[68:76]))
		hash = [32]byte(header[4:36])
	}
	return times
}

// child mines a coinbase child of parent at the same-branch lower median plus one under the expected target.
func (w *ssqWorld) child(parent [32]byte, height uint64, accept func([32]byte) bool) []byte {
	w.t.Helper()
	times := w.timestamps(parent, int(min(height, 11))) //nolint:gosec // at most 11.
	slices.Sort(times)
	target := [32]byte(w.headers[parent][76:108])
	if height%10_080 == 0 {
		window := w.timestamps(parent, 10_080)
		slices.Reverse(window)
		var err error
		if target, err = consensus.RetargetV1Clamped(target, window); err != nil {
			w.t.Fatalf("retarget: %v", err)
		}
	}
	return w.childAt(parent, times[(len(times)-1)/2]+1, target, accept)
}

// childAt mines a coinbase child of parent at an explicit timestamp and target.
func (w *ssqWorld) childAt(parent [32]byte, timestamp uint64, target [32]byte, accept func([32]byte) bool) []byte {
	w.t.Helper()
	block := ssqMine(w.t, parent, timestamp, target, accept)
	w.absent = append(w.absent, ssqHash(block))
	return block
}

// ssqRetarget is the literal §15 result for both named boundary windows: every clamped step is 120 or 113 seconds, so
// T_actual = 120*10079-7 = 1209473 against T_expected = 1209600 and target = floor(POW_LIMIT*1209473/1209600).
func ssqRetarget() [32]byte {
	var target [32]byte
	limit := new(big.Int).SetBytes(consensus.POW_LIMIT[:])
	new(big.Int).Div(new(big.Int).Mul(limit, big.NewInt(1_209_473)), big.NewInt(1_209_600)).FillBytes(target[:])
	return target
}

func ssqID(rank uint8, key []byte) mdbx.ConsultedRow { return mdbx.ConsultedRow{DBI: ssqDBIs[rank], Key: key} }

func ssqAuthorityID() mdbx.ConsultedRow { return ssqID(0, []byte{2}) }

func ssqForwardID(k uint64) mdbx.ConsultedRow { return ssqID(2, ssqMust(mdbx.HeightKey(1, k))) }

func ssqOwnerID(hash [32]byte) mdbx.ConsultedRow {
	return ssqID(7, ssqMust(mdbx.CanonicalOwnerKey(1, hash)))
}

func ssqHeaderID(hash [32]byte) mdbx.ConsultedRow { return ssqID(3, bytes.Clone(hash[:])) }

func ssqBodyID(hash [32]byte) mdbx.ConsultedRow { return ssqID(4, bytes.Clone(hash[:])) }

func ssqLinkID(height uint64) mdbx.ConsultedRow { return ssqID(6, ssqMust(mdbx.HeightKey(2, height))) }

// canonicalIDs is the canonical-parent evidence: authority, the parent's forward/owner pair and count headers.
func (w *ssqWorld) canonicalIDs(k uint64, count int) []mdbx.ConsultedRow {
	ids := []mdbx.ConsultedRow{ssqAuthorityID(), ssqForwardID(k), ssqOwnerID(w.canonical[k])}
	for hash, i := w.canonical[k], 0; i < count; i++ {
		ids = append(ids, ssqHeaderID(hash))
		hash = [32]byte(w.headers[hash][4:36])
	}
	return ids
}

// selectedIDs is the selected-parent evidence: authority, tip link and body, count headers, the owner row of each
// height above F and the paired F rows when F is in the window.
func (w *ssqWorld) selectedIDs(count int) []mdbx.ConsultedRow {
	s := w.spec.side
	hash := w.side[s.tip]
	ids := []mdbx.ConsultedRow{ssqAuthorityID(), ssqLinkID(s.tip), ssqBodyID(hash)}
	for i := 0; i < count; i++ {
		r := s.tip - uint64(i) //nolint:gosec // i < count <= tip+1.
		ids = append(ids, ssqHeaderID(hash))
		if r > s.f {
			ids = append(ids, ssqOwnerID(hash))
		} else if r == s.f {
			ids = append(ids, ssqForwardID(r), ssqOwnerID(hash))
		}
		hash = [32]byte(w.headers[hash][4:36])
	}
	return ids
}

// comparatorIDs is the comparison-only selected tip: link, owner row and header, never its body.
func (w *ssqWorld) comparatorIDs() []mdbx.ConsultedRow {
	tip := w.side[w.spec.side.tip]
	return []mdbx.ConsultedRow{ssqLinkID(w.spec.side.tip), ssqOwnerID(tip), ssqHeaderID(tip)}
}

func ssqSorted(rows []mdbx.ConsultedRow) []mdbx.ConsultedRow {
	rows = slices.Clone(rows)
	slices.SortFunc(rows, func(a, b mdbx.ConsultedRow) int { return cmp.Or(cmp.Compare(a.DBI.Rank, b.DBI.Rank), bytes.Compare(a.Key, b.Key)) })
	return rows
}

// want is the expected qualification: the summary from public parse/weight owners, literal heights and works.
func (w *ssqWorld) want(raw []byte, parent [32]byte, parentHeight, f uint64, parentWork, work [40]byte, selected bool, ids []mdbx.ConsultedRow) selectedSideQualification {
	w.t.Helper()
	tx, _, _, _, err := consensus.ParseTx(raw[consensus.BLOCK_HEADER_BYTES+1:])
	if err != nil {
		w.t.Fatalf("ParseTx: %v", err)
	}
	// The one-output coinbase candidate is base 103, witness 1, DA prefix 1: literal weight 414 and DA 0.
	weight, da, _, err := consensus.TxWeightAndStats(tx)
	if err != nil || weight != 414 || da != 0 {
		w.t.Fatalf("candidate weight %d DA %d (%v), want literal 414/0", weight, da, err)
	}
	authority, err := mdbx.DecodeStorageAuthorityV1(w.rows[string([]byte{0, 2})].value)
	if err != nil {
		w.t.Fatalf("authority decode: %v", err)
	}
	summary := consensus.BlockBasicSummary{TxCount: 1, SumWeight: weight, SumDa: da, BlockHash: ssqHash(raw)}
	return selectedSideQualification{
		Summary: summary, Selected: selected, ParentHash: parent, ParentHeight: parentHeight, F: f, Height: parentHeight + 1,
		ParentWork: parentWork, Work: work, Authority: authority, Consulted: ssqSorted(ids),
	}
}

func ssqWantOK(t *testing.T, label string, got selectedSideQualification, err error, want selectedSideQualification) {
	t.Helper()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got %+v/%v\nwant %+v", label, got, err, want)
	}
}

func ssqWantZero(t *testing.T, label string, got selectedSideQualification) {
	t.Helper()
	if !reflect.DeepEqual(got, selectedSideQualification{}) {
		t.Fatalf("%s: nonzero qualification %+v", label, got)
	}
}

// ssqWantResult requires the exact classified result and no recheck request anywhere in the chain.
func ssqWantResult(t *testing.T, label string, got selectedSideQualification, err error, result string) {
	t.Helper()
	var failure *selectedSideQualificationError
	var request *selectedSideDamageRequest
	if !errors.As(err, &failure) || failure.Result != result || errors.As(err, &request) {
		t.Fatalf("%s: got %v, want %s without a request", label, err, result)
	}
	ssqWantZero(t, label, got)
}

// ssqWantRequest requires the exact recheck locator and no classified failure.
func ssqWantRequest(t *testing.T, label string, got selectedSideQualification, err error, want selectedSideDamageRequest) {
	t.Helper()
	var failure *selectedSideQualificationError
	var request *selectedSideDamageRequest
	if !errors.As(err, &request) || *request != want || errors.As(err, &failure) {
		t.Fatalf("%s: got %v, want request %+v", label, err, want)
	}
	ssqWantZero(t, label, got)
}

func ssqWantTx(t *testing.T, label string, got selectedSideQualification, err error, code consensus.ErrorCode, msg string) {
	t.Helper()
	var txErr *consensus.TxError
	if !errors.As(err, &txErr) || txErr.Code != code || txErr.Msg != msg {
		t.Fatalf("%s: got %v, want %s %q", label, err, code, msg)
	}
	ssqWantZero(t, label, got)
}

// ssqWantEngine requires an unclassified EngineError tuple returned unchanged; code 0 leaves the numeric code unpinned.
func ssqWantEngine(t *testing.T, label string, got selectedSideQualification, err error, class mdbx.EngineClass, operation string, code int, diagnostic string) {
	t.Helper()
	var engine *mdbx.EngineError
	var failure *selectedSideQualificationError
	if !errors.As(err, &engine) || engine.Class != class || engine.Operation != operation || (code != 0 && engine.Code != code) || engine.Diagnostic != diagnostic || errors.As(err, &failure) {
		t.Fatalf("%s: got %v, want %s/%s/%d %q", label, err, operation, class, code, diagnostic)
	}
	ssqWantZero(t, label, got)
}

func TestSelectedSideQualificationCanonical(t *testing.T) {
	w := newSSQWorld(t, ssqSpec{tip: 7})
	for _, c := range []struct {
		k                 uint64
		parent, candidate string
		timestamp         uint64
	}{
		{0, "53e0b78383ca9fac37300280c8cb487feee2d6fa865191bc9ae52f7475062a76", "7a40f39b6a0c9f041788ac7c0b28d24cc183ee46d6d4d6a7f9253476c0ad1f5c", 1_000_001},
		{5, "afec2aae5205a06248b158a4c5e47d46df7f80545365f784ff2393c62da243ad", "bb2c2034c392d611a17633411406d3658d193a5ec4938d1fabf86a980b4afa07", 1_000_241},
	} {
		parent := w.canonical[c.k]
		raw := w.child(parent, c.k+1, nil)
		got, err := w.run(raw)
		ssqWantOK(t, "canonical parent", got, err, w.want(raw, parent, c.k, c.k, ssqWork(c.k+1), ssqWork(c.k+2), true, w.canonicalIDs(c.k, int(min(c.k+1, 11))))) //nolint:gosec // at most 11.
		ssqWantLiteral(t, "canonical parent", got, raw, c.parent, c.candidate, c.timestamp)
	}
}

// ssqWantLiteral binds a result to independently authored ParentHash, candidate BlockHash and candidate timestamp.
func ssqWantLiteral(t *testing.T, label string, got selectedSideQualification, raw []byte, parent, candidate string, timestamp uint64) {
	t.Helper()
	p, perr := hex.DecodeString(parent)
	c, cerr := hex.DecodeString(candidate)
	if perr != nil || cerr != nil || !bytes.Equal(got.ParentHash[:], p) || !bytes.Equal(got.Summary.BlockHash[:], c) || binary.LittleEndian.Uint64(raw[68:76]) != timestamp {
		t.Fatalf("%s: parent %x candidate %x timestamp %d, want literals %s %s %d", label, got.ParentHash, got.Summary.BlockHash, binary.LittleEndian.Uint64(raw[68:76]), parent, candidate, timestamp)
	}
}

func TestSelectedSideQualificationSelected(t *testing.T) {
	for _, c := range []struct {
		name              string
		spec              ssqSpec
		count             int
		parent, candidate string
		mtp               uint64
	}{
		{"full C1", ssqSpec{tip: 5, side: &ssqSideSpec{f: 5, tip: 6, rows: 1}}, 7,
			"7f1379efc05d781c0ca91c060f47f6d66264de449791d38bc0748c958d9c666d", "ccabc71105aa50282a4379ad0c9af87a927aaac5ab44ad07cd7c5c129957ed2c", 1_000_360},
		{"full C1439", ssqSpec{side: &ssqSideSpec{f: 0, tip: 1_439, from: 1_429, rows: 1_439}}, 11,
			"c642afb25a59295c7cbf5cee34f3e16286c9a659085eef7ecb0e746168fa7190", "76c91bb417f7fbdd39f551e6c2def73134000bc1210298cf3bc523bb30920a37", 1_172_073},
		{"one-slot C1440", ssqSpec{side: &ssqSideSpec{f: 0, tip: 1_440, from: 1_430, rows: 1_439}}, 11,
			"4d93e20bf3c4deef1bbdaeb2e58cbe3a27fac12efc21f3bbc1eba85a44ea0d6d", "9fc9de5d48e6a38ea0bc68a61863f8f75ec6da7160740d1c6916b46529f5227d", 1_172_193},
	} {
		w := newSSQWorld(t, c.spec)
		s := w.spec.side
		raw := w.child(w.side[s.tip], s.tip+1, nil)
		got, err := w.run(raw)
		ssqWantOK(t, c.name, got, err, w.want(raw, w.side[s.tip], s.tip, s.f, ssqWork(s.tip+1), ssqWork(s.tip+2), true, w.selectedIDs(c.count)))
		ssqWantLiteral(t, c.name, got, raw, c.parent, c.candidate, c.mtp+1)
	}
}

// ssqWantWindow proves the literal lower median of the same-branch window: at the median the candidate is old, one
// above median+MAX_FUTURE_DRIFT it is future, both under the literal retarget.
func ssqWantWindow(t *testing.T, w *ssqWorld, tip [32]byte, height, median uint64) {
	t.Helper()
	got, err := w.run(w.childAt(tip, median, ssqRetarget(), nil))
	ssqWantTx(t, "at literal median", got, err, consensus.BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median")
	got, err = w.run(w.childAt(tip, median+7_201, ssqRetarget(), nil))
	ssqWantTx(t, "above literal future bound", got, err, consensus.BLOCK_ERR_TIMESTAMP_FUTURE, "timestamp exceeds future drift")
	if height%10_080 != 0 {
		t.Fatalf("window height %d is not a retarget boundary", height)
	}
}

// ssqWantBoundary binds a retarget-boundary result to the literal target, nonce 0, parent/candidate hashes, identity
// count and the oldest (10080th) header identity.
func ssqWantBoundary(t *testing.T, label string, got selectedSideQualification, raw []byte, ids int, parent, candidate, oldest string) {
	t.Helper()
	target, err := hex.DecodeString("fff91e80d6fc5eb4da3c92b81a7095f84e73d62c51b40a2f91e80d6fc5eb4da2")
	o, oerr := hex.DecodeString(oldest)
	if err != nil || oerr != nil || ssqRetarget() != [32]byte(target) || !bytes.Equal(raw[76:108], target) || binary.LittleEndian.Uint64(raw[108:116]) != 0 || len(got.Consulted) != ids ||
		!slices.ContainsFunc(got.Consulted, func(row mdbx.ConsultedRow) bool { return reflect.DeepEqual(row, ssqHeaderID([32]byte(o))) }) {
		t.Fatalf("%s: literal target/nonce/evidence mismatch (%d identities)", label, len(got.Consulted))
	}
	ssqWantLiteral(t, label, got, raw, parent, candidate, binary.LittleEndian.Uint64(raw[68:76]))
}

func TestSelectedSideQualificationHistory(t *testing.T) {
	// One-slot tip 10079, F 8639, count 1439, first 8641, child h10080: 8639 canonical-prefix headers, the Owned F
	// anchor and 1440 side headers whose times differ from canonical-height times.
	w := newSSQWorld(t, ssqSpec{owned: 8_639, tip: 8_639, side: &ssqSideSpec{f: 8_639, tip: 10_079, rows: 1_439}})
	tip := w.side[10_079]
	// Literal context: side times are 1000000+120j-7, so the lower median of heights 10079..10069 is height 10074's
	// 2208873, and the retarget window 0..10079 gives ssqRetarget; old/future bounds distinguish that exact window.
	ssqWantWindow(t, w, tip, 10_080, 2_208_873)
	raw := w.childAt(tip, 2_208_874, ssqRetarget(), nil)
	got, err := w.run(raw)
	ssqWantOK(t, "h10080", got, err, w.want(raw, tip, 10_079, 8_639, ssqWork(10_080), ssqWork(10_081), true, w.selectedIDs(10_080)))
	ssqWantBoundary(t, "h10080", got, raw, 11_525, "6aa0141803fe72a211356610f4db476c182b2d6a523c5e107a309974bba2fbb1",
		"6a4afa7a904fa9c97a9bca5d15e2a54f0cc3600161c88f4c07f38595149f6f14", "53e0b78383ca9fac37300280c8cb487feee2d6fa865191bc9ae52f7475062a76")
	for _, c := range []struct {
		height  uint64
		request bool
	}{{8_640, false}, {8_641, true}} {
		hash := w.side[c.height]
		header := w.headers[hash]
		w.apply([]mdbx.Mutation{w.absentRow(3, bytes.Clone(hash[:]))})
		got, err := w.run(raw)
		if c.request {
			ssqWantRequest(t, "unusable first", got, err, selectedSideDamageRequest{Generation: 2, Tip: 10_079, Height: 8_641})
		} else {
			ssqWantResult(t, "unusable first-1", got, err, ssqBranch)
		}
		w.apply([]mdbx.Mutation{w.literal(3, bytes.Clone(hash[:]), header, false)})
	}
	// h20160: window 10080..20159 with canonical rows above F at the same heights but later times.
	w = newSSQWorld(t, ssqSpec{from: 10_080, owned: 20_148, tip: 20_159, side: &ssqSideSpec{f: 20_148, tip: 20_159, rows: 11}})
	tip = w.side[20_159]
	// Side median 3418473 is seven below the canonical-height median 3418480; a canonical-height window would make
	// this candidate old.
	ssqWantWindow(t, w, tip, 20_160, 3_418_473)
	raw = w.childAt(tip, 3_418_474, ssqRetarget(), nil)
	got, err = w.run(raw)
	ssqWantOK(t, "h20160", got, err, w.want(raw, tip, 20_159, 20_148, ssqWork(20_160), ssqWork(20_161), true, w.selectedIDs(10_080)))
	ssqWantBoundary(t, "h20160", got, raw, 10_096, "b342fabeae2d07e9be77259915379565f758494b497a8925212f33ffae0c7691",
		"9a090af51b85a22e76095e223a37b653de91731c12b7339df90a12d709674afe", "fc839e69fef8bacb18cdaad33d3bfda5dfd36e4c1c6704afcd425c735aa5d4f3")
	// Unproved F and a paired Owned F anchor at another height are branch data.
	w = newSSQWorld(t, ssqSpec{tip: 5, side: &ssqSideSpec{f: 5, tip: 6, rows: 1}})
	raw = w.child(w.side[6], 7, nil)
	c4, c5 := w.canonical[4], w.canonical[5]
	w.apply([]mdbx.Mutation{
		w.literal(2, ssqMust(mdbx.HeightKey(1, 4)), mdbx.ChainValue(c5, c4, ssqWork(5)), true),
		w.absentRow(2, ssqMust(mdbx.HeightKey(1, 5))),
		w.absentRow(7, ssqMust(mdbx.CanonicalOwnerKey(1, c4))),
		w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, c5)), mdbx.CanonicalOwnerValue(4), true),
	})
	got, err = w.run(raw)
	ssqWantResult(t, "Owned F anchor at height 4", got, err, ssqBranch)
	w.apply([]mdbx.Mutation{w.absentRow(2, ssqMust(mdbx.HeightKey(1, 4))), w.absentRow(7, ssqMust(mdbx.CanonicalOwnerKey(1, c5)))})
	got, err = w.run(raw)
	ssqWantResult(t, "unproved F", got, err, ssqBranch)
}

func TestSelectedSideQualificationSelection(t *testing.T) {
	w := newSSQWorld(t, ssqSpec{tip: 5, side: &ssqSideSpec{f: 2, tip: 4, rows: 2, work: 6}})
	c5, sideTip := w.canonical[5], w.side[4]
	ids := append(w.canonicalIDs(5, 6), w.comparatorIDs()...)
	for _, c := range []struct {
		name     string
		work     uint64
		accept   func([32]byte) bool
		selected bool
	}{
		{"greater work", 6, nil, true},
		{"lower work", 8, nil, false},
		{"equal work smaller hash", 7, func(h [32]byte) bool { return bytes.Compare(h[:], sideTip[:]) < 0 }, true},
		{"equal work larger hash", 7, func(h [32]byte) bool { return bytes.Compare(h[:], sideTip[:]) > 0 }, false},
	} {
		w.spec.side.work = c.work
		w.apply([]mdbx.Mutation{w.authorityMutation(w.authorityValue())}, []mdbx.Mutation{w.literal(6, ssqMust(mdbx.HeightKey(2, 4)), mdbx.ChainValue(sideTip, w.side[3], ssqWork(c.work)), true)})
		raw := w.child(c5, 6, c.accept)
		got, err := w.run(raw)
		ssqWantOK(t, c.name, got, err, w.want(raw, c5, 5, 5, ssqWork(6), ssqWork(7), c.selected, ids))
	}
	// A healthy comparison-only tip needs no body; an actual linking parent does.
	w = newSSQWorld(t, ssqSpec{tip: 5, side: &ssqSideSpec{f: 2, tip: 4, rows: 2, work: 6, noBody: true}})
	raw := w.child(w.canonical[5], 6, nil)
	got, err := w.run(raw)
	ssqWantOK(t, "comparator without body", got, err, w.want(raw, w.canonical[5], 5, 5, ssqWork(6), ssqWork(7), true, append(w.canonicalIDs(5, 6), w.comparatorIDs()...)))
	got, err = w.run(w.child(w.side[4], 5, nil))
	ssqWantRequest(t, "linking parent without body", got, err, selectedSideDamageRequest{Generation: 2, Tip: 4, Height: 4})
}

func TestSelectedSideQualificationEvidence(t *testing.T) {
	w := newSSQWorld(t, ssqSpec{tip: 5, side: &ssqSideSpec{f: 5, tip: 6, rows: 1, work: 3}})
	c5 := w.canonical[5]
	raw := w.child(c5, 6, nil)
	got, err := w.run(raw)
	want := w.want(raw, c5, 5, 5, ssqWork(6), ssqWork(7), true, append(w.canonicalIDs(5, 6), w.comparatorIDs()...))
	ssqWantOK(t, "canonical parent with comparator", got, err, want)
	// Neither raw nor a returned key is shared with the result or a later invocation.
	clear(raw[:consensus.BLOCK_HEADER_BYTES])
	ssqWantOK(t, "after raw mutation", got, nil, want)
	for _, row := range got.Consulted {
		clear(row.Key)
	}
	raw = w.child(c5, 6, nil)
	got, err = w.run(raw)
	ssqWantOK(t, "fresh invocation", got, err, w.want(raw, c5, 5, 5, ssqWork(6), ssqWork(7), true, append(w.canonicalIDs(5, 6), w.comparatorIDs()...)))
	// A completed setup Update removing the selected side is recomputed by the next invocation.
	w.spec.side = nil
	w.apply([]mdbx.Mutation{w.authorityMutation(w.authorityValue())})
	got, err = w.run(raw)
	ssqWantOK(t, "after side removal", got, err, w.want(raw, c5, 5, 5, ssqWork(6), ssqWork(7), true, w.canonicalIDs(5, 6)))
}

// ssqPrune, ssqPendingNone, ssqReplay and ssqOrdinary are the legal authority shapes of the control table cells.
func ssqPrune(recovery bool) func(*mdbx.StorageAuthorityV1) {
	return func(a *mdbx.StorageAuthorityV1) {
		a.B, a.U, a.Phase = 1, 13_681, mdbx.StoragePhasePruneGCV1
		a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanBlocksV1, GenerationID: 1}}}
		if recovery {
			ssqPendingNone(a)
		}
	}
}

func ssqPendingNone(a *mdbx.StorageAuthorityV1) {
	profile := mdbx.StorageProfileArchiveV1
	a.Lifecycle, a.PendingTargetProfile = mdbx.StorageLifecycleRecoveryRequiredV1, &profile
}

func ssqReplay(a *mdbx.StorageAuthorityV1) {
	a.Phase, a.Lifecycle = mdbx.StoragePhaseReplayV1, mdbx.StorageLifecycleRecoveryRequiredV1
	target := mdbx.RecoveryTargetV1{ChainID: [32]byte{11}, GenesisHash: [32]byte{12}, TipHash: [32]byte{13}, TipHeight: 2, CumulativeChainwork: ssqWork(1)}
	a.Replay = &mdbx.ReplayV1{TargetProfile: mdbx.StorageProfileArchiveV1, TargetGenerationID: 2, Target: target, Cursor: mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorPreGenesisV1}}
}

func ssqOrdinary(a *mdbx.StorageAuthorityV1) {
	oldPoint, newPoint := mdbx.AuthorityPointV1{Height: 5, BlockHash: [32]byte{0x51}}, mdbx.AuthorityPointV1{Height: 5, BlockHash: [32]byte{0x52}}
	a.Phase, a.Lifecycle = mdbx.StoragePhaseOrdinaryApplyV1, mdbx.StorageLifecycleRecoveryRequiredV1
	a.Ordinary = &mdbx.OrdinaryApplyV1{
		Stage: mdbx.OrdinaryStageDisconnectV1, Target: newPoint, OldSuffix: []mdbx.AuthorityPointV1{oldPoint}, NewSuffix: []mdbx.AuthorityPointV1{newPoint},
		CapturedSelectedSide: &mdbx.SelectedSideV1{GenerationID: 2, F: 4, TipHeight: 5, TipHash: newPoint.BlockHash, CumulativeChainwork: ssqWork(1), RowCount: 1, LogicalBytes: 1},
	}
}

func TestSelectedSideQualificationControl(t *testing.T) {
	w := newSSQWorld(t, ssqSpec{tip: 5})
	c5 := w.canonical[5]
	raw := w.child(c5, 6, nil)
	oversized := make([]byte, mdbx.MaxBlockBytes+1)
	for _, c := range []struct {
		name   string
		edit   func(*mdbx.StorageAuthorityV1)
		result string
	}{
		{"NONE/STABLE", nil, ""},
		{"PRUNE_GC/STABLE", ssqPrune(false), ""},
		{"NONE/RECOVERY_REQUIRED", ssqPendingNone, ssqRequired},
		{"PRUNE_GC/RECOVERY_REQUIRED", ssqPrune(true), ssqRequired},
		{"REPLAY/RECOVERY_REQUIRED", ssqReplay, ssqRequired},
		{"ORDINARY_APPLY/RECOVERY_REQUIRED", ssqOrdinary, ssqRecovery},
	} {
		w.spec.authority, w.spec.b = c.edit, 0
		w.apply([]mdbx.Mutation{w.authorityMutation(w.authorityValue())})
		got, err := w.run(raw)
		if c.result == "" {
			ssqWantOK(t, c.name, got, err, w.want(raw, c5, 5, 5, ssqWork(6), ssqWork(7), true, w.canonicalIDs(5, 6)))
			continue
		}
		ssqWantResult(t, c.name, got, err, c.result)
		got, err = w.run(oversized)
		ssqWantResult(t, c.name+" before raw bound", got, err, c.result)
	}
}

func TestSelectedSideQualificationParent(t *testing.T) {
	w := newSSQWorld(t, ssqSpec{tip: 5, side: &ssqSideSpec{f: 2, tip: 4, rows: 2}})
	orphan := ssqHeader(w.canonical[5], [32]byte{}, ssqTime(6), consensus.POW_LIMIT, 77)
	orphanHash := ssqHash(orphan)
	w.apply([]mdbx.Mutation{w.literal(3, bytes.Clone(orphanHash[:]), orphan, false)})
	w.headers[orphanHash] = orphan
	for _, c := range []struct {
		name   string
		parent [32]byte
		height uint64
	}{{"header-only parent", orphanHash, 7}, {"interior fork parent", w.side[3], 4}} {
		got, err := w.run(w.child(c.parent, c.height, nil))
		ssqWantResult(t, c.name, got, err, ssqBranch)
	}
	// A truncated candidate header maps to BLOCK_ERR_PARSE before any owner lookup: this handle is unverified.
	w.reopen()
	got, err := w.run(w.child(w.canonical[5], 6, nil)[:100])
	ssqWantTx(t, "truncated header", got, err, consensus.BLOCK_ERR_PARSE, "invalid block header")
}

func TestSelectedSideQualificationCanonicalEvidence(t *testing.T) {
	w := newSSQWorld(t, ssqSpec{tip: 5})
	raw := w.child(w.canonical[5], 6, nil)
	w.setEntry(5, [32]byte{0x77})
	got, err := w.run(raw)
	ssqWantResult(t, "header/index-prev disagreement", got, err, ssqIntegrity)
	w.setEntry(5, w.canonical[4])
	w.reopen()
	got, err = w.run(raw)
	ssqWantEngine(t, "unverified handle", got, err, mdbx.EngineInvalidInput, "get", 22, "canonical owner index is not verified")
}

func TestSelectedSideQualificationSelectedEvidence(t *testing.T) {
	w := newSSQWorld(t, ssqSpec{tip: 3, side: &ssqSideSpec{f: 2, tip: 4, rows: 2}})
	tip, prev := w.side[4], w.side[3]
	raw := w.child(tip, 5, nil)
	request := selectedSideDamageRequest{Generation: 2, Tip: 4, Height: 4}
	w.relink([32]byte{0x99}, prev, 5)
	got, err := w.run(raw)
	ssqWantResult(t, "link names another hash", got, err, ssqIntegrity)
	for _, c := range []struct {
		name string
		prev [32]byte
		work uint64
	}{{"link parent mismatch", [32]byte{0x66}, 5}, {"link work mismatch", prev, 6}} {
		w.relink(tip, c.prev, c.work)
		got, err := w.run(raw)
		ssqWantRequest(t, c.name, got, err, request)
	}
	w.relink(tip, prev, 5)
	body := w.rows[string(append([]byte{4}, tip[:]...))].value
	w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
	got, err = w.run(raw)
	ssqWantRequest(t, "missing linking body", got, err, request)
	w.apply([]mdbx.Mutation{w.literal(4, bytes.Clone(tip[:]), body, false)})
	got, err = w.run(raw)
	ssqWantOK(t, "restored", got, err, w.want(raw, tip, 4, 2, ssqWork(5), ssqWork(6), true, w.selectedIDs(5)))
}

func TestSelectedSideQualificationDomains(t *testing.T) {
	var limit, belowLimit [40]byte
	limit[3] = 1
	for i := 4; i < 40; i++ {
		belowLimit[i] = 0xff
	}
	for _, c := range []struct {
		name     string
		tip      uint64
		work     [40]byte
		admitted [40]byte
	}{
		{"height 0x100000000", 0xffff_ffff, ssqWork(1), [40]byte{}},
		{"work above 2^288", 20, limit, [40]byte{}},
		{"height 0xffffffff and work 2^288", 0xffff_fffe, belowLimit, limit},
	} {
		w := newSSQWorld(t, ssqSpec{from: c.tip - 10, tip: c.tip, work: func(uint64) [40]byte { return c.work }})
		parent := w.canonical[c.tip]
		raw := w.child(parent, c.tip+1, nil)
		got, err := w.run(raw)
		if c.admitted == ([40]byte{}) {
			ssqWantResult(t, c.name, got, err, ssqBranch)
		} else {
			ssqWantOK(t, c.name, got, err, w.want(raw, parent, c.tip, c.tip, c.work, c.admitted, true, w.canonicalIDs(c.tip, 11)))
		}
	}
	// An invalid candidate target is decided at step 2, before selection and domain arithmetic.
	w := newSSQWorld(t, ssqSpec{from: 10, tip: 20, work: func(uint64) [40]byte { return limit }})
	got, err := w.run(ssqBlock(t, w.canonical[20], ssqTime(21), [32]byte{}, 0, true))
	ssqWantTx(t, "invalid target", got, err, consensus.BLOCK_ERR_TARGET_INVALID, "target out of range")
}

func TestSelectedSideQualificationCapacity(t *testing.T) {
	w := newSSQWorld(t, ssqSpec{tip: 5})
	got, err := w.run(make([]byte, mdbx.MaxBlockBytes+1))
	ssqWantResult(t, "raw above M", got, err, ssqBranch)
}

// ssqUpdate qualifies inside a no-write Update that stops with a private sentinel after observation.
func (w *ssqWorld) update(raw []byte) (selectedSideQualification, error, mdbx.CommitTruth, mdbx.UpdateStage) {
	w.t.Helper()
	defer w.wantRaw(raw, bytes.Clone(raw))
	sentinel := errors.New("qualification observed")
	var got selectedSideQualification
	var qerr error
	truth, stage, err := w.store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
		got, qerr = qualifySelectedSideMDBX(r, raw)
		if qerr != nil {
			return mdbx.Batch{}, qerr
		}
		return mdbx.Batch{}, sentinel
	})
	if qerr == nil && err == sentinel { //nolint:errorlint // Only the exact invocation-local sentinel with no infrastructure cause is success.
		err = nil
	}
	w.wantImage("after no-write Update")
	return got, err, truth, stage
}

func TestSelectedSideQualificationNoMutation(t *testing.T) {
	w := newSSQWorld(t, ssqSpec{tip: 5, side: &ssqSideSpec{f: 2, tip: 4, rows: 2, work: 6, noBody: true}})
	c5 := w.canonical[5]
	winner := w.child(c5, 6, nil)
	old := ssqMine(t, c5, 1, consensus.POW_LIMIT, nil)
	w.absent = append(w.absent, ssqHash(old))
	for _, c := range []struct {
		name  string
		raw   []byte
		check func(selectedSideQualification, error)
	}{
		{"success", winner, func(got selectedSideQualification, err error) {
			ssqWantOK(t, "success", got, err, w.want(winner, c5, 5, 5, ssqWork(6), ssqWork(7), true, append(w.canonicalIDs(5, 6), w.comparatorIDs()...)))
		}},
		{"consensus refusal", old, func(got selectedSideQualification, err error) {
			ssqWantTx(t, "old timestamp", got, err, consensus.BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median")
		}},
		{"damage refusal", w.child(w.side[4], 5, nil), func(got selectedSideQualification, err error) {
			ssqWantRequest(t, "missing body", got, err, selectedSideDamageRequest{Generation: 2, Tip: 4, Height: 4})
		}},
		{"eligibility refusal", w.child(w.side[3], 4, nil), func(got selectedSideQualification, err error) { ssqWantResult(t, "interior parent", got, err, ssqBranch) }},
	} {
		got, err, truth, stage := w.update(c.raw)
		c.check(got, err)
		if truth != mdbx.CommitTruthOld || stage != mdbx.UpdateStagePrewrite {
			t.Fatalf("%s: truth/stage %v/%v", c.name, truth, stage)
		}
	}
	// A loser is a nil-error qualification with Selected false.
	w.spec.side.work = 9
	w.apply([]mdbx.Mutation{w.authorityMutation(w.authorityValue())}, []mdbx.Mutation{w.literal(6, ssqMust(mdbx.HeightKey(2, 4)), mdbx.ChainValue(w.side[4], w.side[3], ssqWork(9)), true)})
	got, err, truth, stage := w.update(winner)
	ssqWantOK(t, "loser", got, err, w.want(winner, c5, 5, 5, ssqWork(6), ssqWork(7), false, append(w.canonicalIDs(5, 6), w.comparatorIDs()...)))
	if truth != mdbx.CommitTruthOld || stage != mdbx.UpdateStagePrewrite {
		t.Fatalf("loser truth/stage %v/%v", truth, stage)
	}
	// Context refusal: no canonical height is Owned, so the promised F anchor is unproved.
	w = newSSQWorld(t, ssqSpec{tip: 2, owned: 3, side: &ssqSideSpec{f: 2, tip: 4, rows: 2}})
	got, err, truth, stage = w.update(w.child(w.side[4], 5, nil))
	ssqWantResult(t, "unproved F context", got, err, ssqBranch)
	if truth != mdbx.CommitTruthOld || stage != mdbx.UpdateStagePrewrite {
		t.Fatalf("context truth/stage %v/%v", truth, stage)
	}
}

func TestSelectedSideQualificationLifetime(t *testing.T) {
	w := newSSQWorld(t, ssqSpec{tip: 5})
	raw := w.child(w.canonical[5], 6, nil)
	var saved *mdbx.Reader
	if err := w.store.View(func(r *mdbx.Reader) error { saved = r; return nil }); err != nil {
		t.Fatalf("View: %v", err)
	}
	got, err := qualifySelectedSideMDBX(saved, raw)
	ssqWantEngine(t, "saved Reader", got, err, mdbx.EngineInvalidInput, "get", 22, "Reader is not active")
	w.wantImage("after saved Reader")
	// Mutating the input after return changes neither the scalars nor any key of the result.
	got, err = w.run(raw)
	want := w.want(raw, w.canonical[5], 5, 5, ssqWork(6), ssqWork(7), true, w.canonicalIDs(5, 6))
	for i := range raw {
		raw[i] ^= 0xff
	}
	ssqWantOK(t, "after input mutation", got, err, want)
}
