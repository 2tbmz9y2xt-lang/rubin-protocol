//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

/*
#include "../../../../third_party/libmdbx/mdbx.h"
*/
import "C"

import (
	"bytes"
	"math"
	"runtime"
	"slices"
	"sort"
	"unsafe"
)

// ---- tree_truth_cgo.go and mdbx_cgo.go (owner L3) ----
// Native access (D14-8, D14-9): tree_truth_cgo.go reaches MDBX only through Go functions in mdbx_cgo.go (the fixture interceptors
// exist only in its preamble): the D14-9 wrappers (txn-begin over rubin_mdbx_txn_begin, RDONLY or READWRITE; ordered point/next;
// one single-identity delete with the updateNativeDeletes law) and existing Go functions of that file (updateNativePut,
// updateNativeEqual, legacy Pair, final-equality and readback helpers). Every tree seam begins ORIGINAL OLD through the begin
// wrapper after arming. A failed native read (rc not SUCCESS or NOTFOUND) is nativeError(operationUpdate, rc), returned
// unchanged. No L3 function calls releaseV1 on the ledger it is given (D14-12); the P budget, S_r and B_r are released by L5a.

// treeBorrowV1 views a native image; the bytes stay valid only while txn lives and is not written at that identity.
func treeBorrowV1(image updateImage) (treeImageV1, error) {
	if uint64(image.length) > uint64(math.MaxInt) {
		return treeImageV1{}, updateNativeInvariant("mdbx_get returned invalid result shape")
	}
	if !image.present || image.length == 0 {
		return treeImageV1{present: image.present}, nil
	}
	return treeImageV1{present: true, value: unsafe.Slice((*byte)(image.bytes), int(image.length))}, nil
}

const (
	treeEntryImageV1 uint8 = iota + 1
	treeEntryAbsentV1
	treeEntryReferenceV1
)

// treeEntryV1 is one owned P entry: a present image, an absent marker or a reference to ORIGINAL OLD (D2-1, D12-C).
type treeEntryV1 struct {
	dbi        DBI
	key, value []byte
	kind       uint8
	links      uint8
	oldPresent bool
}

// treeProjectionV1 is P_w or P_r: entries ordered by (DBI rank, key), never map order; live counts D2-7 entry bytes.
type treeProjectionV1 struct {
	entries []treeEntryV1
	live    uint64
}

func treeEntrySizeV1(key, value []byte) uint64 { return uint64(len(key)) + uint64(len(value)) }

func treeEntryOrderV1(dbi DBI, key []byte, entry treeEntryV1) int {
	if dbi.Rank != entry.dbi.Rank {
		return int(dbi.Rank) - int(entry.dbi.Rank)
	}
	return bytes.Compare(key, entry.key)
}

// findV1 returns the first index whose identity is >= (dbi, key) and whether it is that identity.
func (p *treeProjectionV1) findV1(dbi DBI, key []byte) (int, bool) {
	i := sort.Search(len(p.entries), func(i int) bool { return treeEntryOrderV1(dbi, key, p.entries[i]) <= 0 })
	return i, i < len(p.entries) && treeEntryOrderV1(dbi, key, p.entries[i]) == 0
}

// sizeAtV1 is the entry size P holds at i, or 0 when i is not that identity.
func (p *treeProjectionV1) sizeAtV1(i int, found bool) uint64 {
	if !found {
		return 0
	}
	return treeEntrySizeV1(p.entries[i].key, p.entries[i].value)
}

// storeV1 copies the identity into P at i; the caller has already covered its size.
func (p *treeProjectionV1) storeV1(i int, found bool, dbi DBI, key []byte, kind uint8, value []byte) {
	entry := treeEntryV1{dbi: dbi, key: append([]byte(nil), key...), kind: kind}
	if kind == treeEntryImageV1 {
		entry.value = append(make([]byte, 0, len(value)), value...)
	}
	replaced := p.sizeAtV1(i, found)
	if found {
		p.entries[i] = entry
	} else {
		p.entries = append(p.entries, treeEntryV1{})
		copy(p.entries[i+1:], p.entries[i:])
		p.entries[i] = entry
	}
	p.live = p.live + treeEntrySizeV1(entry.key, entry.value) - replaced
}

// treeAfterV1 is the P entry kind and value of a planned image. An absent target carries no value into P, so its
// entry size is len(key) whatever after.value holds (D2-7).
func treeAfterV1(after treeImageV1) (uint8, []byte) {
	if after.present {
		return treeEntryImageV1, after.value
	}
	return treeEntryAbsentV1, nil
}

// treeExpectedV1 is the native expectation of an image or absent entry.
func treeExpectedV1(entry treeEntryV1) (updateImage, error) {
	if entry.kind == treeEntryAbsentV1 {
		return updateImage{}, nil
	}
	return updateOwnedImage(entry.value)
}

func treeSnapshotMismatchV1() error {
	return adapterError(operationUpdate, EngineStateMismatch, codeProblem, "OLD/write snapshot mismatch", nil)
}

func treeInvalidInputV1() error { return updateNativeInvariant("invalid native update input") }

// treeAmendedV1 returns P over ORIGINAL OLD. Checked raw reads compare that
// amended image with the write txn; covered reads compare physical ORIGINAL
// before P can shadow a point or any native successor (D2-2, D3 S).
type treeAmendedV1 struct {
	old, write *C.MDBX_txn
	handles    [9]C.MDBX_dbi
	covered    bool
	p          *treeProjectionV1
	section    *treeSectionV1
	readLimit  uint64
}

func (a *treeAmendedV1) logicalV1(dbi DBI, key []byte) (treeImageV1, error) {
	if dbi.Rank >= 9 {
		return treeImageV1{}, treeInvalidInputV1()
	}
	if i, found := a.p.findV1(dbi, key); found && a.p.entries[i].kind != treeEntryReferenceV1 {
		entry := a.p.entries[i]
		return treeImageV1{present: entry.kind == treeEntryImageV1, value: entry.value, planned: true, links: entry.links}, nil
	}
	return a.pointV1(dbi, key)
}

func (a *treeAmendedV1) getV1(dbi DBI, key []byte) (treeImageV1, error) {
	image, err := a.logicalV1(dbi, key)
	if err != nil || a.write == nil {
		return image, err
	}
	expected := image
	if a.covered {
		expected, err = a.pointV1(dbi, key)
		if err != nil {
			return treeImageV1{}, err
		}
	}
	equal, err := a.pointEqualV1(dbi, key, expected)
	if err != nil {
		return treeImageV1{}, err
	}
	if !equal {
		return treeImageV1{}, treeSnapshotMismatchV1()
	}
	return image, nil
}

func (a *treeAmendedV1) nextV1(dbi DBI, from []byte) ([]byte, treeImageV1, bool, error) {
	if dbi.Rank >= 9 {
		return nil, treeImageV1{}, false, treeInvalidInputV1()
	}
	key, image, ok, err := a.mergedNextV1(dbi, from)
	if err != nil || a.write == nil || a.covered {
		return key, image, ok, err
	}
	equal, err := a.nextEqualV1(dbi, from, key, image, ok)
	if err != nil {
		return nil, treeImageV1{}, false, err
	}
	if !equal {
		return nil, treeImageV1{}, false, treeSnapshotMismatchV1()
	}
	return key, image, ok, nil
}

// mergedNextV1 merges ORIGINAL OLD with P's image and absent entries; a P entry shadows the same OLD identity.
func (a *treeAmendedV1) mergedNextV1(dbi DBI, from []byte) ([]byte, treeImageV1, bool, error) {
	at, _ := a.p.findV1(dbi, from)
	seek := from
	for {
		at = a.skipReferencesV1(dbi, at)
		nativeKey, native, nativeOK, err := a.nativeNextV1(dbi, seek)
		if err != nil {
			return nil, treeImageV1{}, false, err
		}
		key, image, ok, shadowed := a.chooseV1(dbi, at, nativeKey, native, nativeOK)
		if !shadowed {
			return key, image, ok, nil
		}
		seek, at = append(append(make([]byte, 0, len(key)+1), key...), 0), at+1
	}
}

// nativeNextV1 checks each physical successor before P can hide or precede it.
func (a *treeAmendedV1) nativeNextV1(dbi DBI, seek []byte) ([]byte, treeImageV1, bool, error) {
	key, image, ok, err := a.physicalNextV1(dbi, seek)
	if err != nil || !a.covered || a.write == nil {
		return key, image, ok, err
	}
	equal, err := a.nextEqualV1(dbi, seek, key, image, ok)
	if err != nil {
		return nil, treeImageV1{}, false, err
	}
	if !equal {
		return nil, treeImageV1{}, false, treeSnapshotMismatchV1()
	}
	return key, image, ok, nil
}

// pointV1 admits native OLD before handing its borrowed view to a consumer.
func (a *treeAmendedV1) pointV1(dbi DBI, key []byte) (treeImageV1, error) {
	if a.section == nil {
		return treeReadPointBoundedV1(a.old, a.handles[dbi.Rank], key, nil, a.readLimit)
	}
	return a.section.pointV1(dbi, key)
}

// pointEqualV1 keeps mutable credit inside the writer call only.
func (a *treeAmendedV1) pointEqualV1(dbi DBI, key []byte, image treeImageV1) (bool, error) {
	if a.section == nil {
		return treePointEqualV1(a.write, a.handles[dbi.Rank], key, image, nil, a.readLimit)
	}
	t := a.section
	budget := treePairReadBudgetV1{credit: t.pairReadLimit, ledger: t.ledger}
	defer t.publishReadV1(&budget)
	return treePointEqualV1(a.write, a.handles[dbi.Rank], key, image, &budget, 0)
}

// physicalNextV1 covers even successors hidden by P's merge.
func (a *treeAmendedV1) physicalNextV1(dbi DBI, seek []byte) ([]byte, treeImageV1, bool, error) {
	if a.section == nil {
		return treeReadNextBoundedV1(a.old, a.handles[dbi.Rank], seek, nil, a.readLimit)
	}
	t := a.section
	budget := treePairReadBudgetV1{credit: t.pairReadLimit, ledger: t.ledger}
	defer t.publishReadV1(&budget)
	return treeReadNextBoundedV1(a.old, a.handles[dbi.Rank], seek, &budget, 0)
}

// nextEqualV1 preserves key-before-value comparison at the candidate position.
func (a *treeAmendedV1) nextEqualV1(dbi DBI, seek, key []byte, image treeImageV1, ok bool) (bool, error) {
	if a.section == nil {
		return treeNextEqualV1(a.write, a.handles[dbi.Rank], seek, key, image, ok, nil, a.readLimit)
	}
	t := a.section
	budget := treePairReadBudgetV1{credit: t.pairReadLimit, ledger: t.ledger}
	defer t.publishReadV1(&budget)
	return treeNextEqualV1(a.write, a.handles[dbi.Rank], seek, key, image, ok, &budget, 0)
}

func (a *treeAmendedV1) skipReferencesV1(dbi DBI, at int) int {
	for at < len(a.p.entries) && a.p.entries[at].dbi.Rank == dbi.Rank && a.p.entries[at].kind == treeEntryReferenceV1 {
		at++
	}
	return at
}

// chooseV1 picks the smaller of the native row and P entry at; shadowed reports an absent marker to step over.
func (a *treeAmendedV1) chooseV1(dbi DBI, at int, nativeKey []byte, native treeImageV1, nativeOK bool) ([]byte, treeImageV1, bool, bool) {
	inP := at < len(a.p.entries) && a.p.entries[at].dbi.Rank == dbi.Rank
	if !inP || nativeOK && bytes.Compare(nativeKey, a.p.entries[at].key) < 0 {
		return nativeKey, native, nativeOK, false
	}
	entry := a.p.entries[at]
	if entry.kind == treeEntryAbsentV1 {
		return entry.key, treeImageV1{}, false, true
	}
	return entry.key, treeImageV1{present: true, value: entry.value, planned: true, links: entry.links}, true, false
}

// treeSectionV1 is the write section of one tree operation: write txn, P_w and its high-water P budget.
type treeSectionV1 struct {
	env           *C.MDBX_env
	handles       [9]C.MDBX_dbi
	old, write    *C.MDBX_txn
	ledger        treeLedgerV1
	reached       UpdateStage
	pw            treeProjectionV1
	heldP         uint64
	references    []updateReference
	ended         bool
	covered       bool
	pairOnly      bool
	pairReadLimit uint64
}

// beginTreeSectionV1 begins the write txn with updateNativeExecute's begin path. On failure it returns nil and that
// path's outcome unchanged.
func beginTreeSectionV1(env *C.MDBX_env, dbis [9]C.MDBX_dbi, old *C.MDBX_txn, ledger treeLedgerV1) (*treeSectionV1, updateNativeOutcome) {
	write, err := treeBeginV1(env, true)
	if err != nil {
		if write != nil {
			return nil, updateNativeRetainedWrite(false, err, nil, write, UpdateStagePrewrite)
		}
		return nil, updateNativeConsumed(CommitTruthOld, false, err, nil, UpdateStagePrewrite)
	}
	return &treeSectionV1{env: env, handles: dbis, old: old, write: write, ledger: ledger, reached: UpdateStagePrewrite}, updateNativeOutcome{}
}

func (t *treeSectionV1) oldV1(checked bool) treeOldV1 {
	amended := &treeAmendedV1{old: t.old, handles: t.handles, p: &t.pw, covered: t.covered, section: t}
	if checked {
		amended.write = t.write
	}
	return amended
}

func (t *treeSectionV1) writerV1() treeEmitterV1 { return treeWriterEmitterV1{t} }

// recordV1 charges only the shortfall above the free P budget before copying the entry into P_w (D5-2).
func (t *treeSectionV1) recordV1(dbi DBI, key []byte, kind uint8, value []byte) error {
	i, found := t.pw.findV1(dbi, key)
	n := treeEntrySizeV1(key, value)
	if free := t.heldP - t.pw.live; n > free {
		err := t.ledger.chargeV1(n - free)
		if err != nil {
			return err
		}
		t.heldP += n - free
	}
	t.pw.storeV1(i, found, dbi, key, kind, value)
	return t.requireReadV1(uint64(len(value)))
}

// publishReadV1 retains earlier successful growth even when later work fails.
func (t *treeSectionV1) publishReadV1(budget *treePairReadBudgetV1) {
	t.pairReadLimit = budget.credit + budget.extra // coverV1 checked this sum before admitting extra.
}

// requireReadV1 declares future native candidate capacity, separately from P.
func (t *treeSectionV1) requireReadV1(n uint64) error {
	budget := treePairReadBudgetV1{credit: t.pairReadLimit, ledger: t.ledger}
	defer t.publishReadV1(&budget)
	return budget.requireV1(n)
}

// pointV1 admits future native OLD capacity at the existing point observation.
func (t *treeSectionV1) pointV1(dbi DBI, key []byte) (treeImageV1, error) {
	budget := treePairReadBudgetV1{credit: t.pairReadLimit, ledger: t.ledger}
	defer t.publishReadV1(&budget)
	return treeReadPointBoundedV1(t.old, t.handles[dbi.Rank], key, &budget, 0)
}

// oldMatchV1 preserves the original snapshot comparison and native error order.
func (t *treeSectionV1) oldMatchV1(dbi DBI, key []byte, diagnostic string) error {
	budget := treePairReadBudgetV1{credit: t.pairReadLimit, ledger: t.ledger}
	defer t.publishReadV1(&budget)
	equal, err := updateNativePairOldEqual(t.old, t.write, t.handles[dbi.Rank], key, &budget)
	if err != nil {
		return err
	}
	if !equal {
		return adapterError(operationUpdate, EngineStateMismatch, codeProblem, diagnostic, nil)
	}
	return nil
}

// matchV1 covers the candidate; callers retain the exact existing expected producer.
// Raw fused callers use V, prior P, a prior complete native window, C or node L;
// covered flush and final callers use P. The later raw P copy is never this grant.
func (t *treeSectionV1) matchV1(dbi DBI, key []byte, expected updateImage, diagnostic string) error {
	budget := treePairReadBudgetV1{credit: t.pairReadLimit, ledger: t.ledger}
	defer t.publishReadV1(&budget)
	equal, err := updateNativePairEqual(t.write, t.handles[dbi.Rank], key, expected, false, &budget, 0)
	if err != nil {
		return err
	}
	if !equal {
		return adapterError(operationUpdate, EngineStateMismatch, codeProblem, diagnostic, nil)
	}
	return nil
}

// writeTargetV1 applies D14-10 and fused final equality. Raw callers supply
// logical prior presence; covered flush supplies frozen physical ORIGINAL
// presence after complete preflight. This owner does not derive either mode.
func (t *treeSectionV1) writeTargetV1(target treeTargetV1, prior bool) error {
	handle := t.handles[target.dbi.Rank]
	if prior {
		one := [1]ownedMutation{{dbi: target.dbi, key: target.key, beforePresent: true}}
		err := updateNativeDeletes(t.write, t.handles, one[:], &t.reached)
		if err != nil {
			return err
		}
	}
	expected := updateImage{}
	if target.after.present {
		image, err := updateOwnedImage(target.after.value)
		if err != nil {
			return err
		}
		err = updateNativePut(t.write, handle, target.key, image, target.after.value, &t.reached)
		if err != nil {
			return err
		}
		expected = image
	}
	err := t.matchV1(target.dbi, target.key, expected, "final update image mismatch")
	runtime.KeepAlive(target.after.value)
	return err
}

// pairPreflightV1 runs updateNativePreflight semantics for every Pair target and Consulted row (write txn vs
// ORIGINAL OLD), including updateNativePairing (N1/N2/O1/O2; refusal canonicalPairingError, OLD/Prewrite/-1,
// plan consumed). It runs right after beginTreeSectionV1 and before primitive 0 (D12-F).
func (t *treeSectionV1) pairPreflightV1(pair []ownedMutation, consulted []ownedConsulted) error {
	_, err := updateNativeImages(t.old, t.handles, pair)
	if err != nil {
		return err
	}
	return t.pairReadPreflightV1(pair, consulted, nil)
}

// pairPreflightScopedV1 is pairPreflightV1 with the plan's one residual scope (context window or physical
// scope) as one more consulted domain.
func (t *treeSectionV1) pairPreflightScopedV1(pair []ownedMutation, consulted []ownedConsulted, residual *treePlanV1) error {
	_, err := updateNativeImages(t.old, t.handles, pair)
	if err != nil {
		return err
	}
	return t.pairReadPreflightV1(pair, consulted, residual)
}

// treeSealScopesV1 sets each synchronous scope copy's funding to the sealed limit with no mutable budget.
func treeSealScopesV1(scopes []largeImageScope, limit uint64) {
	for i := range scopes {
		scopes[i].pairBudget, scopes[i].pairLimit = nil, limit
	}
}

// scopedMatchV1 compares the residual plan's scope, excluding the plan's targets, under OLD/write; a
// nil residual compares nothing. The one scope copy draws from the caller's mutable preflight budget,
// which stays on the caller's stack.
func (t *treeSectionV1) scopedMatchV1(pair []ownedMutation, budget *treePairReadBudgetV1, residual *treePlanV1) error {
	if residual == nil {
		return updateNativeScopedMatch(t.old, t.write, t.handles, pair, nil, "OLD/write snapshot mismatch")
	}
	funded := [1]largeImageScope{residual.residualScopeV1()}
	funded[0].pairBudget, funded[0].pairLimit = budget, 0
	return updateNativeScopedMatch(t.old, t.write, t.handles, pair, nil, "OLD/write snapshot mismatch", funded[:]...)
}

// pairReadPreflightV1 admits Pair/owner windows for both operation modes. The
// section keeps the scalar high-water; primitives may still grow it before commit.
// Scoped context work is funded independently.
func (t *treeSectionV1) pairReadPreflightV1(pair []ownedMutation, consulted []ownedConsulted, residual *treePlanV1) error {
	budget := treePairReadBudgetV1{credit: t.pairReadLimit, ledger: t.ledger}
	defer t.publishReadV1(&budget)
	var err error
	for _, side := range canonicalSides {
		err = canonicalNewPaired(pair, side, &budget)
		if err != nil {
			return err
		}
	}
	for _, side := range canonicalSides {
		err = canonicalOldPaired(t.old, t.handles, pair, side, &budget)
		if err != nil {
			return err
		}
	}
	err = t.pairReadTargetsV1(pair, &budget)
	if err != nil {
		return err
	}
	err = updateNativePairConsultedMatch(t.old, t.write, t.handles, consulted, "OLD/write snapshot mismatch", &budget, 0)
	if err != nil {
		return err
	}
	err = t.scopedMatchV1(pair, &budget, residual)
	if err != nil {
		return err
	}
	return t.pairReadSealV1(pair, &budget)
}

// pairReadTargetsV1 keeps target OLD/write comparisons ahead of consulted rows.
func (t *treeSectionV1) pairReadTargetsV1(pair []ownedMutation, budget *treePairReadBudgetV1) error {
	for _, m := range pair {
		equal, err := updateNativePairOldEqual(t.old, t.write, t.handles[m.dbi.Rank], m.key, budget)
		if err != nil {
			return err
		}
		if !equal {
			return adapterError(operationUpdate, EngineStateMismatch, codeProblem, "OLD/write snapshot mismatch", nil)
		}
	}
	return nil
}

// pairReadSealV1 funds future NEW candidates before the first Pair emission.
func (t *treeSectionV1) pairReadSealV1(pair []ownedMutation, budget *treePairReadBudgetV1) error {
	var err error
	for _, m := range pair {
		if m.after == AfterLiteral {
			err = budget.requireV1(uint64(len(m.literal)))
			if err != nil {
				return err
			}
		}
	}
	t.pairReadLimit, err = budget.availableV1()
	return err
}

// pairReadFinalV1 uses the established Pair capacity and unchanged scope owner.
// The last primitive final-equality return fixes the scalar carried into commit.
func (t *treeSectionV1) pairReadFinalV1(pair []ownedMutation, consulted []ownedConsulted, scopes ...largeImageScope) error {
	err := updateNativePairVerify(t.write, t.handles, pair, t.pairReadLimit)
	if err != nil {
		return err
	}
	err = updateNativePairConsultedMatch(t.old, t.write, t.handles, consulted, "final update image mismatch", nil, t.pairReadLimit)
	if err != nil {
		return err
	}
	treeSealScopesV1(scopes, t.pairReadLimit)
	return updateNativeScopedMatch(t.old, t.write, t.handles, pair, nil, "final update image mismatch", scopes...)
}

// pairEmitV1 writes the Pair after the last primitive: all deletes, then all puts (legacy order).
func (t *treeSectionV1) pairEmitV1(pair []ownedMutation) error {
	err := updateNativeDeletes(t.write, t.handles, pair, &t.reached)
	if err != nil {
		return err
	}
	return updateNativePuts(t.old, t.write, t.handles, pair, t.references, &t.reached)
}

// freezeV1 checks every P identity against ORIGINAL, then fixes physical presence.
// Pair conflicts are operation-owned refusals; no source is invoked by this pass.
func (t *treeSectionV1) freezeV1(pair []ownedMutation, consulted []ownedConsulted) error {
	for i := range t.pw.entries {
		e := &t.pw.entries[i]
		if treeProjectionConflictV1(*e, pair, consulted) {
			return updateInvalidBatch()
		}
		err := t.oldMatchV1(e.dbi, e.key, "OLD/write snapshot mismatch")
		if err != nil {
			return err
		}
		image, err := t.pointV1(e.dbi, e.key)
		if err != nil {
			return err
		}
		e.oldPresent = image.present
	}
	return nil
}

func treeProjectionConflictV1(e treeEntryV1, pair []ownedMutation, consulted []ownedConsulted) bool {
	if canonicalTargetIndex(pair, e.dbi.Rank, e.key) >= 0 {
		return true
	}
	if e.kind == treeEntryReferenceV1 {
		return false
	}
	return obsoleteConsultedContains(consulted, e.dbi.Rank, e.key)
}

// headerSlotV1 decides plan's header slot (RUB-1750) after Proof returns nil and before the first write, with reads only:
// the OLD/write equality check of row x (its ORIGINAL OLD and write images), then one more ORIGINAL OLD read of x.
// Absent joins the Pair as an expected-absent insert of Header; a byte-identical row joins the Consulted rows; any
// other present value, including another width or an empty value, refuses with no write. Both joins keep (rank, key)
// order inside the step-5 spare capacity, so flushV1, finalV1 and the readback cover the slot as an ordinary Pair
// target or Consulted row.
func (t *treeSectionV1) headerSlotV1(plan *treePlanV1) error {
	if plan.slot == nil {
		return nil
	}
	key, header := plan.slot[:32:32], plan.slot[32:]
	err := t.oldMatchV1(schemaDBIs[3], key, "OLD/write snapshot mismatch")
	if err != nil {
		return err
	}
	image, err := t.pointV1(schemaDBIs[3], key)
	if err != nil {
		return err
	}
	if !image.present {
		err = t.requireReadV1(uint64(len(header)))
		if err != nil {
			return err
		}
		plan.pair = treeSlotInsertV1(plan.pair, ownedMutation{dbi: schemaDBIs[3], key: key, after: AfterLiteral, literal: header})
		return nil
	}
	equal, err := treeOwnedPointEqualV1(image, header, t.pairReadLimit)
	if err != nil {
		return err
	}
	if !equal {
		return adapterError(operationUpdate, EngineStateMismatch, codeProblem, "tree header slot differs", nil)
	}
	plan.consulted = treeSlotConsultedV1(plan.consulted, ownedConsulted{dbi: schemaDBIs[3], key: key})
	return nil
}

// treeSlotInsertV1 inserts m at its (rank, key) position. Tree Pairs carry no AfterOldValueRef, so the preflight
// references are empty and no index moves.
func treeSlotInsertV1(pair []ownedMutation, m ownedMutation) []ownedMutation {
	at := treePairAtV1(pair, m.dbi.Rank, m.key)
	pair = append(pair, m)
	copy(pair[at+1:], pair[at:len(pair)-1])
	pair[at] = m
	return pair
}

// treePairAtV1 binary-searches the (rank, key) ordered owned Pair for the insertion position.
func treePairAtV1(pair []ownedMutation, rank uint8, key []byte) int {
	at, _ := slices.BinarySearchFunc(pair, treeRowKeyV1{rank: rank, key: key}, treeOwnedCmpV1)
	return at
}

func treeOwnedCmpV1(m ownedMutation, k treeRowKeyV1) int { return treeRowCmpV1(m.dbi.Rank, m.key, k) }

func treeOwnedConsultedCmpV1(row ownedConsulted, k treeRowKeyV1) int {
	return treeRowCmpV1(row.dbi.Rank, row.key, k)
}

// treeSlotConsultedV1 inserts row at its binary-searched (rank, key) position.
func treeSlotConsultedV1(consulted []ownedConsulted, row ownedConsulted) []ownedConsulted {
	at, _ := slices.BinarySearchFunc(consulted, treeRowKeyV1{rank: row.dbi.Rank, key: row.key}, treeOwnedConsultedCmpV1)
	consulted = append(consulted, row)
	copy(consulted[at+1:], consulted[at:len(consulted)-1])
	consulted[at] = row
	return consulted
}

// flushV1 consumes only frozen P. All node identities precede every root,
// including ordinary Pair roots. Entries are already in TreeNodeKey order.
func (t *treeSectionV1) flushV1(pair []ownedMutation) error {
	for pass := uint8(0); pass < 3; pass++ {
		if pass == 2 {
			err := t.pairEmitV1(pair)
			if err != nil {
				return err
			}
		}
		err := t.flushPassV1(pass)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *treeSectionV1) flushPassV1(pass uint8) error {
	for _, e := range t.pw.entries {
		if e.kind == treeEntryReferenceV1 || treeFlushPassV1(e) != pass {
			continue
		}
		after := treeImageV1{present: e.kind == treeEntryImageV1, value: e.value}
		err := t.writeTargetV1(treeTargetV1{dbi: e.dbi, key: e.key, after: after}, e.oldPresent)
		if err != nil {
			return err
		}
	}
	return nil
}

func treeFlushPassV1(e treeEntryV1) uint8 {
	if e.dbi.Rank == 8 {
		return 1
	}
	if e.dbi.Rank == 0 && len(e.key) == 9 && e.key[0] == 0x11 {
		return 2
	}
	return 0
}

// finalV1 is complete final pair equality (D2-4): P_w identities, Pair targets, references and Consulted rows.
// It then drops P_w data; the P charge is kept as the P budget (D5-2).
func (t *treeSectionV1) finalV1(pair []ownedMutation, consulted []ownedConsulted) error {
	const diagnostic = "final update image mismatch"
	for _, entry := range t.pw.entries {
		err := t.finalEntryV1(entry, diagnostic)
		if err != nil {
			return err
		}
	}
	err := t.pairReadFinalV1(pair, consulted)
	if err != nil {
		return err
	}
	t.pw = treeProjectionV1{}
	return nil
}

// finalScopedV1 is finalV1 with the plan's residual scope compared after the Consulted rows.
func (t *treeSectionV1) finalScopedV1(pair []ownedMutation, consulted []ownedConsulted, residual *treePlanV1) error {
	const diagnostic = "final update image mismatch"
	for _, entry := range t.pw.entries {
		err := t.finalEntryV1(entry, diagnostic)
		if err != nil {
			return err
		}
	}
	err := t.pairReadFinalV1(pair, consulted, residual.residualScopeV1())
	if err != nil {
		return err
	}
	t.pw = treeProjectionV1{}
	return nil
}

func (t *treeSectionV1) finalEntryV1(entry treeEntryV1, diagnostic string) error {
	if entry.kind == treeEntryReferenceV1 {
		return t.oldMatchV1(entry.dbi, entry.key, diagnostic)
	}
	expected, err := treeExpectedV1(entry)
	if err != nil {
		return err
	}
	err = t.matchV1(entry.dbi, entry.key, expected, diagnostic)
	runtime.KeepAlive(entry.value)
	return err
}

func (t *treeSectionV1) pBudgetV1() uint64 { return t.heldP }

func (t *treeSectionV1) abortV1(primary error) updateNativeOutcome {
	t.ended = true
	return updateNativeAbort(t.write, primary, t.reached)
}

func (t *treeSectionV1) commitV1(pair []ownedMutation, consulted []ownedConsulted, truth treeTruthV1) updateNativeOutcome {
	t.ended = true
	return updateNativeCommit(t.env, t.handles, pair, consulted, t.old, t.write, t.reached, truth)
}

// commitScopedV1 is commitV1 with the plan's residual scope forwarded to the pair-only readback.
func (t *treeSectionV1) commitScopedV1(pair []ownedMutation, consulted []ownedConsulted, truth treeTruthV1, residual *treePlanV1) updateNativeOutcome {
	t.ended = true
	return updateNativeCommit(t.env, t.handles, pair, consulted, t.old, t.write, t.reached, truth, residual.residualScopeV1())
}

// treeWriterEmitterV1 is the writer-position emitter over one section.
type treeWriterEmitterV1 struct{ section *treeSectionV1 }

func (e treeWriterEmitterV1) emitV1(target treeTargetV1) error {
	t := e.section
	if t.covered {
		kind, value := treeAfterV1(target.after)
		err := t.recordV1(target.dbi, target.key, kind, value)
		if err != nil {
			return err
		}
		i, _ := t.pw.findV1(target.dbi, target.key)
		t.pw.entries[i].links = target.after.links
		if !bytes.Equal(t.pw.entries[i].value, value) {
			return updateNativeInvariant("projected update image mismatch")
		}
		return nil
	}
	prior, err := t.oldV1(false).getV1(target.dbi, target.key)
	if err != nil {
		return err
	}
	err = t.writeTargetV1(target, prior.present)
	if err != nil {
		return err
	}
	kind, value := treeAfterV1(target.after)
	return t.recordV1(target.dbi, target.key, kind, value)
}

func (e treeWriterEmitterV1) referV1(dbi DBI, key []byte) error {
	t := e.section
	if dbi.Rank >= 9 {
		return treeInvalidInputV1()
	}
	if _, found := t.pw.findV1(dbi, key); found {
		return nil
	}
	return t.recordV1(dbi, key, treeEntryReferenceV1, nil)
}

// treeReadbackStateV1 holds P_r and a scalar native seal inside one strict snapshot.
type treeReadbackStateV1 struct {
	old, read   *C.MDBX_txn
	handles     [9]C.MDBX_dbi
	budget      *treeBudgetV1
	pr          treeProjectionV1
	failed      error
	nativeLimit uint64
	bounded     bool
	oldImage    bool
	newImage    bool
	replay      *treePlanV1
}

// newTreeReadbackV1 is called only when the plan has at least one primitive. It draws S_r at construction and each
// P_r entry at its emitV1/referV1; a failed draw returns errOperationReservationCapacity (D5-5 structural stop).
func newTreeReadbackV1(old, read *C.MDBX_txn, dbis [9]C.MDBX_dbi, budget *treeBudgetV1, nativeLimit uint64) (*treeReadbackStateV1, error) {
	if budget == nil || !budget.drawV1(treeScratchBytesV1) {
		return nil, errOperationReservationCapacity
	}
	return &treeReadbackStateV1{old: old, read: read, handles: dbis, budget: budget, nativeLimit: nativeLimit}, nil
}

func (r *treeReadbackStateV1) oldV1() treeOldV1 {
	return &treeAmendedV1{old: r.old, handles: r.handles, p: &r.pr, readLimit: r.nativeLimit}
}

func (r *treeReadbackStateV1) emitterV1() treeEmitterV1 { return treeReadbackEmitterV1{r} }

// recordV1 draws the new entry first and returns a replaced entry after it (D14-7); the first failure stops the
// readback (RS): every later emission returns it without a draw.
func (r *treeReadbackStateV1) recordV1(dbi DBI, key []byte, kind uint8, value []byte) error {
	if r.failed != nil {
		return r.failed
	}
	if dbi.Rank >= 9 {
		r.failed = treeInvalidInputV1()
		return r.failed
	}
	i, found := r.pr.findV1(dbi, key)
	if !r.budget.drawV1(treeEntrySizeV1(key, value)) {
		r.failed = errOperationReservationCapacity
		return r.failed
	}
	if found {
		r.budget.returnV1(r.pr.sizeAtV1(i, found))
	}
	r.pr.storeV1(i, found, dbi, key, kind, value)
	return nil
}

// verdictV1 completes both predicates over P_r, references, the Pair targets and Consulted rows even after one is false:
// OLD if OLD matches, else NEW, else UNKNOWN. Pair rows carry no AfterOldValueRef (D14-5, D14-11).
func (r *treeReadbackStateV1) verdictV1(pair []ownedMutation, consulted []ownedConsulted, scopes ...largeImageScope) (CommitTruth, error) {
	if r.failed != nil {
		return CommitTruthUnknown, r.failed
	}
	oldImage, newImage, err := r.foldProjectionV1()
	if err != nil {
		return CommitTruthUnknown, err
	}
	oldImage, newImage, err = r.foldPairV1(pair, consulted, oldImage, newImage, scopes...)
	if err != nil {
		return CommitTruthUnknown, err
	}
	equal, err := r.replay.replayEqualV1(r.read, r.handles)
	if err != nil {
		return CommitTruthUnknown, err
	}
	if !equal {
		oldImage, newImage = false, false
	}
	if oldImage {
		return CommitTruthOld, nil
	}
	if newImage {
		return CommitTruthNew, nil
	}
	return CommitTruthUnknown, nil
}

// replayOriginalV1 qualifies only the declared CURRENT absent undo prefix in protected OLD.
func (p *treePlanV1) replayOriginalV1(old *C.MDBX_txn, dbis [9]C.MDBX_dbi) error {
	if !p.preserveReplay || p.primitives[0].Undo != UndoTransientV1 {
		return nil
	}
	equal, err := treeReplayUndoAbsentV1(old, dbis[5], p.primitives[0].Block)
	if err == nil && !equal {
		return treeSnapshotMismatchV1()
	}
	return err
}

// replayMatchV1 projects readable inequality at the reached writer phase.
func (p *treePlanV1) replayMatchV1(candidate *C.MDBX_txn, dbis [9]C.MDBX_dbi, diagnostic string) error {
	equal, err := p.replayEqualV1(candidate, dbis)
	if err == nil && !equal {
		return adapterError(operationUpdate, EngineStateMismatch, codeProblem, diagnostic, nil)
	}
	return err
}

// replayEqualV1 completes tip then prefix even when the tip is readably unequal.
func (p *treePlanV1) replayEqualV1(candidate *C.MDBX_txn, dbis [9]C.MDBX_dbi) (bool, error) {
	if p == nil || !p.preserveReplay {
		return true, nil
	}
	tip, err := canonicalTipEqual(candidate, dbis[2], largeImageScope{tip: p.tip})
	if err != nil {
		return false, err
	}
	if p.primitives[0].Undo != UndoTransientV1 {
		return tip, nil
	}
	absent, err := treeReplayUndoAbsentV1(candidate, dbis[5], p.primitives[0].Block)
	return tip && absent, err
}

// treeReplayUndoAbsentV1 exposes at most the physical successor's first 32 key bytes.
func treeReplayUndoAbsentV1(txn *C.MDBX_txn, dbi C.MDBX_dbi, block [32]byte) (bool, error) {
	key, _, found, err := treeNextImagesV1(txn, dbi, block[:])
	if err != nil || !found {
		return !found, err
	}
	key.length = min(key.length, 32)
	view, err := treeBorrowV1(key)
	if err != nil {
		return false, err
	}
	return !bytes.Equal(view.value, block[:]), nil
}

// foldProjectionV1 returns the selected stream's complete folded predicates.
// Fallback compares every P_r identity with ORIGINAL OLD and its planned image
// (ORIGINAL OLD for a reference), in (rank, key) order.
func (r *treeReadbackStateV1) foldProjectionV1() (bool, bool, error) {
	if r.bounded {
		return r.oldImage, r.newImage, nil
	}
	oldImage, newImage := true, true
	for _, entry := range r.pr.entries {
		handle := r.handles[entry.dbi.Rank]
		oldEqual, err := treeOldEqualBoundedV1(r.old, r.read, handle, entry.key, r.nativeLimit)
		if err != nil {
			return false, false, err
		}
		newEqual := oldEqual
		if entry.kind != treeEntryReferenceV1 {
			newEqual, err = r.planEqualV1(handle, entry)
			if err != nil {
				return false, false, err
			}
		}
		oldImage, newImage = oldImage && oldEqual, newImage && newEqual
	}
	return oldImage, newImage, nil
}

func (r *treeReadbackStateV1) planEqualV1(handle C.MDBX_dbi, entry treeEntryV1) (bool, error) {
	expected, err := treeExpectedV1(entry)
	if err != nil {
		return false, err
	}
	equal, err := updateNativePairEqual(r.read, handle, entry.key, expected, false, nil, r.nativeLimit)
	runtime.KeepAlive(entry.value)
	return equal, err
}

// foldPairV1 completes Pair and consulted domains under the immutable native seal.
func (r *treeReadbackStateV1) foldPairV1(pair []ownedMutation, consulted []ownedConsulted, oldImage, newImage bool, scopes ...largeImageScope) (bool, bool, error) {
	_, err := updateNativeImages(r.old, r.handles, pair)
	if err != nil {
		return false, false, err
	}
	oldPair, newPair, err := updateNativePairReadbackTargets(r.old, r.read, r.handles, pair, r.nativeLimit)
	if err != nil {
		return false, false, err
	}
	oldImage, newImage, err = updateNativePairReadbackConsulted(r.old, r.read, r.handles, consulted, oldImage && oldPair, newImage && newPair, r.nativeLimit)
	if err != nil {
		return false, false, err
	}
	treeSealScopesV1(scopes, r.nativeLimit)
	return updateNativeReadbackScoped(r.old, r.read, r.handles, pair, nil, oldImage, newImage, scopes...)
}

// treeReadbackEmitterV1 is the readback-position emitter: it draws from the carried budget and never writes MDBX.
type treeReadbackEmitterV1 struct{ readback *treeReadbackStateV1 }

func (e treeReadbackEmitterV1) emitV1(target treeTargetV1) error {
	kind, value := treeAfterV1(target.after)
	r := e.readback
	if err := r.recordV1(target.dbi, target.key, kind, value); err != nil {
		return err
	}
	i, _ := r.pr.findV1(target.dbi, target.key)
	r.pr.entries[i].links = target.after.links
	return nil
}

func (e treeReadbackEmitterV1) referV1(dbi DBI, key []byte) error {
	r := e.readback
	if r.failed == nil && dbi.Rank < 9 {
		if _, found := r.pr.findV1(dbi, key); found {
			return nil
		}
	}
	return r.recordV1(dbi, key, treeEntryReferenceV1, nil)
}

// treeBoundedEmitterV1 consumes one selected target while its complete expected
// bytes remain held. Preflight owns OLD/write then future NEW extent; writer
// regenerates from protected ORIGINAL OLD with no P or per-node metadata.
type treeBoundedEmitterV1 struct {
	section *treeSectionV1
	pair    []ownedMutation
	writing bool
}

// emitV1 never retains a target. The walk's final root callback writes Pair
// first, then obtains only physical-before metadata and performs fused equality.
func (e treeBoundedEmitterV1) emitV1(target treeTargetV1) error {
	t := e.section
	if !e.writing {
		err := t.oldMatchV1(target.dbi, target.key, "OLD/write snapshot mismatch")
		if err != nil {
			return err
		}
		return t.requireReadV1(uint64(len(target.after.value)))
	}
	if target.dbi.Rank == 0 && len(target.key) == 9 && target.key[0] == 0x11 {
		err := t.pairEmitV1(e.pair)
		if err != nil {
			return err
		}
	}
	prior, err := updateNativeImage(t.old, t.handles[target.dbi.Rank], target.key)
	if err != nil {
		return err
	}
	return t.writeTargetV1(target, prior.present)
}

// referV1 compares every complete kept reference at its owning callback.
func (e treeBoundedEmitterV1) referV1(dbi DBI, key []byte) error {
	diagnostic := "OLD/write snapshot mismatch"
	if e.writing {
		diagnostic = "final update image mismatch"
	}
	return e.section.oldMatchV1(dbi, key, diagnostic)
}

// treeBoundedReadbackEmitterV1 folds both predicates immediately under the
// immutable native seal and local B+B_r+S_r budget, never retaining P. B is
// writer.bodyHeld's stored-body grant retained through crossing for sequential
// strict passes.
type treeBoundedReadbackEmitterV1 struct{ readback *treeReadbackStateV1 }

// emitV1 completes both comparisons even after either accumulated predicate is
// false. A later unavailable domain therefore remains UNKNOWN with its cause.
func (e treeBoundedReadbackEmitterV1) emitV1(target treeTargetV1) error {
	r := e.readback
	handle := r.handles[target.dbi.Rank]
	oldEqual, err := treeOldEqualBoundedV1(r.old, r.read, handle, target.key, r.nativeLimit)
	if err != nil {
		return err
	}
	expected, err := updateOwnedImage(target.after.value)
	if err != nil {
		return err
	}
	expected.present = target.after.present
	newEqual, err := updateNativePairEqual(r.read, handle, target.key, expected, false, nil, r.nativeLimit)
	runtime.KeepAlive(target.after.value)
	if err != nil {
		return err
	}
	r.oldImage, r.newImage = r.oldImage && oldEqual, r.newImage && newEqual
	return nil
}

// referV1 includes kept boundaries in both predicates without retained entries.
func (e treeBoundedReadbackEmitterV1) referV1(dbi DBI, key []byte) error {
	r := e.readback
	equal, err := treeOldEqualBoundedV1(r.old, r.read, r.handles[dbi.Rank], key, r.nativeLimit)
	if err != nil {
		return err
	}
	r.oldImage, r.newImage = r.oldImage && equal, r.newImage && equal
	return nil
}
