//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"encoding/binary"
	"unsafe"
)

// CanonicalContextWindowV1 names ascending canonical-v1 indices and their
// ORIGINAL OLD-selected headers. It is nonpersistent physical image evidence,
// not a header-health or consensus certificate.
// Generation must be nonzero, Count is 1..10080, and FirstHeight and the last
// height must be at most 0xffffffff. Each complete index is 104 bytes; its
// leading 32 OLD bytes select the complete 116-byte header compared unchanged.
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
	copy(headerKey[:], unsafe.Slice((*byte)(index.bytes), 32))
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
func contextPairEqual(old, candidate *Reader, key []byte) (bool, error) {
	index, _, err := contextImage(old, 2, key, 104)
	if err != nil {
		return false, err
	}
	indexEqual, err := updateNativeEqual(candidate.txn, candidate.dbis[2], key, index)
	if err != nil {
		return false, err
	}
	var headerKey [32]byte
	copy(headerKey[:], unsafe.Slice((*byte)(index.bytes), 32))
	header, _, err := contextImage(old, 3, headerKey[:], 116)
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
		match, err := contextPairEqual(old, candidate, key[:])
		if err != nil {
			return false, err
		}
		equal = equal && match
	}
	return equal, nil
}
