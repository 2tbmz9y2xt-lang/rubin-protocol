//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
)

// CanonicalContextWindowV1 names ascending canonical-v1 indices and their
// ORIGINAL OLD-selected headers. It is nonpersistent physical image evidence,
// not a header-health or consensus certificate.
// Generation must be nonzero, Count is 1..10080, and FirstHeight and the last
// height must be at most 0xffffffff. Each complete index is 104 bytes; its
// leading 32 OLD bytes select the complete header compared unchanged: 116
// bytes on the legacy Store.Update path, 148 bytes as TreePairV1.ContextConsulted.
type CanonicalContextWindowV1 struct {
	Generation  uint64
	FirstHeight uint64
	Count       uint32
}

func contextInput(window CanonicalContextWindowV1) error {
	invalid := window.Generation == 0 || window.FirstHeight > 0xffffffff || window.Count == 0
	if invalid {
		return updateInvalidBatch()
	}
	if window.Count > 10_080 {
		return updateBoundError()
	}
	if uint64(window.Count-1) > 0xffffffff-window.FirstHeight {
		return updateInvalidBatch()
	}
	return nil
}

func contextKey(window CanonicalContextWindowV1, offset uint32) [16]byte {
	var key [16]byte
	binary.BigEndian.PutUint64(key[:8], window.Generation)
	binary.BigEndian.PutUint64(key[8:], window.FirstHeight+uint64(offset))
	return key
}

func contextOverlap(plan []ownedMutation, consulted []ownedConsulted, rank uint8, key []byte) bool {
	// Admitted OLD_VALUE_REF identities have ranks 1/5, so cannot match ranks 2/3.
	return canonicalTargetIndex(plan, rank, key) >= 0 || obsoleteConsultedContains(consulted, rank, key)
}

// Admission is scalar/key-only. All index overlaps precede every source query.
func updateOwnedContext(window *CanonicalContextWindowV1, plan []ownedMutation, scope largeImageScope) (largeImageScope, error) {
	if window == nil {
		return scope, nil
	}
	owned := *window
	if err := contextInput(owned); err != nil {
		return largeImageScope{}, err
	}
	for i := uint32(0); i < owned.Count; i++ {
		key := contextKey(owned, i)
		if contextOverlap(plan, scope.consulted, 2, key[:]) {
			return largeImageScope{}, updateInvalidBatch()
		}
	}
	scope.context, scope.contextPresent = owned, true
	return scope, nil
}

// Native errors retain their infrastructure disposition before fixed-width Q.
func contextImage(old *Reader, rank uint8, key []byte, width uint64) (updateImage, bool, error) {
	image, err := updateNativeImage(old.txn, old.dbis[rank], key)
	return contextImageShape(image, err, width)
}

// contextImageShape classifies one ORIGINAL OLD context read: native errors and an invalid native result shape
// ("mdbx_get returned invalid result shape") are infrastructure; absence or another width is the incomplete-image
// StateMismatch.
func contextImageShape(image updateImage, err error, width uint64) (updateImage, bool, error) {
	if err != nil {
		return updateImage{}, true, err
	}
	if !largeNativeShape(image.bytes, uint64(image.length)) {
		return updateImage{}, true, updateNativeInvariant("mdbx_get returned invalid result shape")
	}
	if !image.present || uint64(image.length) != width {
		return updateImage{}, false, adapterError(operationUpdate, EngineStateMismatch, codeProblem, "canonical context OLD image is incomplete", nil)
	}
	return image, false, nil
}

func contextQualifyPair(old *Reader, key []byte, plan []ownedMutation, consulted []ownedConsulted) (bool, error) {
	index, infrastructure, err := contextImage(old, 2, key, 104)
	if err != nil {
		return infrastructure, err
	}
	var headerKey [32]byte
	_, _ = largeImageCopy(headerKey[:], index.bytes, 104, 0)
	if contextOverlap(plan, consulted, 3, headerKey[:]) {
		return false, updateInvalidBatch()
	}
	_, infrastructure, err = contextImage(old, 3, headerKey[:], 116)
	return infrastructure, err
}

func contextQualify(old *Reader, plan []ownedMutation, scope largeImageScope) (bool, error) {
	if !scope.contextPresent {
		return false, nil
	}
	for i := uint32(0); i < scope.context.Count; i++ {
		key := contextKey(scope.context, i)
		infrastructure, err := contextQualifyPair(old, key[:], plan, scope.consulted)
		if err != nil {
			return infrastructure, err
		}
	}
	return false, nil
}

// Only this pair's borrowed spans and copied OLD header identity are live.
// Even an unequal candidate index cannot skip the ORIGINAL OLD header read.
func contextPairEqual(old, candidate *Reader, key []byte, headerWidth uint64) (bool, error) {
	index, _, err := contextImage(old, 2, key, 104)
	if err != nil {
		return false, err
	}
	indexEqual, err := updateNativeEqual(candidate.txn, candidate.dbis[2], key, index)
	if err != nil {
		return false, err
	}
	var headerKey [32]byte
	_, _ = largeImageCopy(headerKey[:], index.bytes, 104, 0)
	header, _, err := contextImage(old, 3, headerKey[:], headerWidth)
	if err != nil {
		return false, err
	}
	headerEqual, err := updateNativeEqual(candidate.txn, candidate.dbis[3], headerKey[:], header)
	return indexEqual && headerEqual, err
}

func contextEqual(old, candidate *Reader, scope largeImageScope) (bool, error) {
	if !scope.contextPresent {
		return true, nil
	}
	equal := true
	for i := uint32(0); i < scope.context.Count; i++ {
		key := contextKey(scope.context, i)
		match, err := contextPairEqual(old, candidate, key[:], contextHeaderWidth(scope))
		if err != nil {
			return false, err
		}
		equal = equal && match
	}
	return equal, nil
}

// contextHeaderWidth is 116 for the legacy zero-value selector and 148 on the format-3 tree path.
func contextHeaderWidth(scope largeImageScope) uint64 {
	if scope.contextTree {
		return 148
	}
	return 116
}

// contextTreeScopeV1 is the context-only scope of an admitted tree window (format-3 widths 104/148).
func contextTreeScopeV1(window CanonicalContextWindowV1) largeImageScope {
	return largeImageScope{context: window, contextPresent: true, contextTree: true}
}

// contextTreeInfrastructureV1 carries a qualification error whose legacy contextImage disposition is
// infrastructure=true; the public entry unwraps it before the OLD abort, which uses the existing consuming
// failure lifecycle.
type contextTreeInfrastructureV1 struct{ err error }

func (e *contextTreeInfrastructureV1) Error() string { return e.err.Error() }

func (e *contextTreeInfrastructureV1) Unwrap() error { return e.err }

// contextTreeAbortV1 splits a prewrite refusal into its inner error and infrastructure disposition.
func contextTreeAbortV1(err error) (error, bool) {
	var wrapped *contextTreeInfrastructureV1
	if errors.As(err, &wrapped) {
		return wrapped.err, true
	}
	return err, false
}

func contextTreeErrorV1(err error, infrastructure bool) error {
	if err != nil && infrastructure {
		return &contextTreeInfrastructureV1{err: err}
	}
	return err
}

// contextTreeAdmitV1 is the charge-free descriptor row: a window is never bound to an ENTRY token.
func contextTreeAdmitV1(pair *TreePairV1) error {
	if pair.ContextConsulted == nil {
		return nil
	}
	if pair.EntryInventory != nil {
		return updateInvalidBatch()
	}
	return contextInput(*pair.ContextConsulted)
}

func contextTreeRowV1(pair *TreePairV1, rank uint8, key []byte) bool {
	k := treeRowKeyV1{rank: rank, key: key}
	_, inPair := slices.BinarySearchFunc(pair.Mutations, k, treeMutationCmpV1)
	_, inConsulted := slices.BinarySearchFunc(pair.Consulted, k, treeConsultedRowCmpV1)
	return inPair || inConsulted
}

// contextTreeOverlapV1 refuses an index key that is a Pair target or Consulted row, before any native read.
func contextTreeOverlapV1(pair *TreePairV1, window CanonicalContextWindowV1) error {
	for i := uint32(0); i < window.Count; i++ {
		key := contextKey(window, i)
		if contextTreeRowV1(pair, 2, key[:]) {
			return updateInvalidBatch()
		}
	}
	return nil
}

// contextTreeQualifyV1 qualifies the window at ORIGINAL OLD over borrowed rows, one pair at a time, lowest
// failing offset first. Postconditions (the 344-byte charge): one pair is processed at a time; the OLD index
// span's last use (the header-key copy) precedes the OLD header read; each candidate span lives only inside its
// native compare.
func contextTreeQualifyV1(e *treePublicEntryV1, pair *TreePairV1, slot *TreeHeaderSlotV1, window CanonicalContextWindowV1) error {
	for i := uint32(0); i < window.Count; i++ {
		key := contextKey(window, i)
		err := contextTreeQualifyPairV1(e, key[:], pair, slot)
		if err != nil {
			return err
		}
	}
	return nil
}

func contextTreeQualifyPairV1(e *treePublicEntryV1, key []byte, pair *TreePairV1, slot *TreeHeaderSlotV1) error {
	image, err := updateNativeImage(e.old, e.store.dbis[2], key)
	index, infrastructure, err := contextImageShape(image, err, 104)
	if err != nil {
		return contextTreeErrorV1(err, infrastructure)
	}
	var headerKey [32]byte
	_, _ = largeImageCopy(headerKey[:], index.bytes, 104, 0)
	if contextTreeRowV1(pair, 3, headerKey[:]) || (slot != nil && bytes.Equal(slot.Hash[:], headerKey[:])) {
		return updateInvalidBatch()
	}
	image, err = updateNativeImage(e.old, e.store.dbis[3], headerKey[:])
	_, infrastructure, err = contextImageShape(image, err, 148)
	return contextTreeErrorV1(err, infrastructure)
}
