//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"io"
	"sort"
	"sync/atomic"
	"unsafe"
)

// LargeImageKindV1 selects a physical large-value domain, without certifying its schema.
type LargeImageKindV1 uint8

const (
	LargeImageBlockBodyV1 LargeImageKindV1 = 1
	LargeImageUndoFamilyV1 LargeImageKindV1 = 2
)

// LargeImageSelectorV1 names a block body or the complete undo key prefix.
type LargeImageSelectorV1 struct {
	Kind LargeImageKindV1
	Hash [32]byte
}

// LargeImageRowV1 exposes immutable metadata and callback-scoped bounded reads.
// Copies share the same expiry; Key always returns an independent copy.
type LargeImageRowV1 struct {
	span *largeImageSpan
}

type largeImageSpan struct {
	reader *Reader
	key []byte
	image updateImage
	rank uint8
	active atomic.Bool
}

type largeNativeRow struct {
	key []byte
	image updateImage
	done bool
}

type largeImageScope struct {
	selectors []LargeImageSelectorV1
	maxKey uint64
}

func largeImageInput(diagnostic string) error {
	return adapterError(operationGet, EngineInvalidInput, codeEINVAL, diagnostic, nil)
}

func largeImageShapeError() error {
	return adapterError(operationGet, EngineLocalInvariant, codeProblem, "invalid native large image result", nil)
}

func largeImageRank(kind LargeImageKindV1) uint8 {
	switch kind {
	case LargeImageBlockBodyV1:
		return 4
	case LargeImageUndoFamilyV1:
		return 5
	}
	return 0
}

func (row LargeImageRowV1) Key() []byte {
	if row.span == nil {
		return nil
	}
	return bytes.Clone(row.span.key)
}

func (row LargeImageRowV1) Present() bool {
	return row.span != nil && row.span.image.present
}

func (row LargeImageRowV1) Length() uint64 {
	if row.span == nil {
		return 0
	}
	return uint64(row.span.image.length)
}

func (row LargeImageRowV1) readInput(dst []byte) error {
	if !row.span.reader.usable() {
		return largeImageInput("Reader is not active")
	}
	if !row.span.active.Load() {
		return largeImageInput("large image row is not active")
	}
	if len(dst) > 65_536 {
		return largeImageInput("ReadAt buffer exceeds 65536 bytes")
	}
	return nil
}

func (row LargeImageRowV1) ReadAt(dst []byte, offset uint64) (int, error) {
	if row.span == nil {
		return 0, largeImageInput("invalid large image row")
	}
	r := row.span.reader
	if !r.usable() {
		return 0, largeImageInput("Reader is not active")
	}
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if err := row.readInput(dst); err != nil {
		return 0, err
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if offset >= row.Length() {
		return 0, io.EOF
	}
	image, err := r.largePoint(row.span.rank, row.span.key)
	if err != nil {
		return 0, r.largeFailure(err)
	}
	if image.present != row.Present() || image.length != row.span.image.length {
		return 0, r.largeFailure(largeImageShapeError())
	}
	return largeImageCopy(dst, image.bytes, row.Length()-offset, offset)
}

// The native span was shape/width checked before this bounded pointer arithmetic.
func largeImageCopy(dst []byte, pointer unsafe.Pointer, remaining, offset uint64) (int, error) {
	n := uint64(len(dst))
	var err error
	if n > remaining {
		n, err = remaining, io.EOF
	}
	copy(dst, unsafe.Slice((*byte)(unsafe.Add(pointer, uintptr(offset))), int(n)))
	return int(n), err
}

func (r *Reader) largeFailure(err error) error {
	if r.failure == nil {
		r.failure = err
	}
	r.active.Store(false)
	return err
}

func (r *Reader) largeVisitInput(selector LargeImageSelectorV1, visitor func(LargeImageRowV1) error) error {
	if !r.usable() {
		return largeImageInput("Reader is not active")
	}
	if visitor == nil {
		return largeImageInput("nil large image visitor")
	}
	if largeImageRank(selector.Kind) == 0 {
		return largeImageInput("invalid large image selector")
	}
	if !r.largeVisit.CompareAndSwap(false, true) {
		return adapterError(operationGet, EngineConcurrency, codeBusy, "large image visit in progress", nil)
	}
	return nil
}

// VisitLargeImageV1 traverses one complete physical domain. The visitor runs
// without getMu, permitting ordinary reads and reads of the current row.
func (r *Reader) VisitLargeImageV1(selector LargeImageSelectorV1, visitor func(LargeImageRowV1) error) error {
	if err := r.largeVisitInput(selector, visitor); err != nil {
		return err
	}
	defer r.largeVisit.Store(false)
	seek := bytes.Clone(selector.Hash[:])
	for {
		row, err := r.largeNext(selector, seek)
		if err != nil || row.done {
			return err
		}
		if err = r.largeVisitRow(selector, row, visitor); err != nil {
			return err
		}
		if selector.Kind == LargeImageBlockBodyV1 {
			return nil
		}
		seek = largeImageAdvance(row.key, r.maxKey)
	}
}

func (r *Reader) largeVisitRow(selector LargeImageSelectorV1, native largeNativeRow, visitor func(LargeImageRowV1) error) (primary error) {
	span := &largeImageSpan{reader: r, key: native.key, image: native.image, rank: largeImageRank(selector.Kind)}
	span.active.Store(true)
	defer func() {
		span.active.Store(false)
		r.getMu.Lock()
		defer r.getMu.Unlock()
		span.image.bytes = nil
		primary, _ = readPrimary(primary, r.failure)
	}()
	return visitor(LargeImageRowV1{span: span})
}

func (r *Reader) largeNext(selector LargeImageSelectorV1, seek []byte) (largeNativeRow, error) {
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if !r.usable() {
		return largeNativeRow{}, largeImageInput("Reader is not active")
	}
	if seek == nil {
		return largeNativeRow{done: true}, nil
	}
	row, err := r.largeFetch(selector, seek)
	if err != nil {
		return largeNativeRow{}, r.largeFailure(err)
	}
	return row, nil
}

// The immediate successor uses one bounded copied key, including maximum-width keys.
func largeImageAdvance(key []byte, maxKey uint64) []byte {
	if uint64(len(key)) < maxKey {
		return append(bytes.Clone(key), 0)
	}
	next := bytes.Clone(key)
	for i := len(next)-1; i >= 0; i-- {
		if next[i] != 255 {
			next[i]++
			return next[:i+1]
		}
	}
	return nil
}

func largeNativeShape(pointer unsafe.Pointer, length uint64) bool {
	widthOK := length <= uint64(^uint(0)>>1) && length <= uint64(^uintptr(0)-uintptr(pointer))
	return widthOK && (length == 0 || pointer != nil)
}

func largeNativeKey(pointer unsafe.Pointer, length, maximum uint64, seek []byte) ([]byte, error) {
	if pointer == nil || length == 0 || length > maximum || !largeNativeShape(pointer, length) {
		return nil, largeImageShapeError()
	}
	key := unsafe.Slice((*byte)(pointer), int(length))
	if bytes.Compare(key, seek) < 0 {
		return nil, largeImageShapeError()
	}
	return bytes.Clone(key), nil
}

func largeSelectorCounts(selectors []LargeImageSelectorV1) error {
	if len(selectors) > 2880 {
		return updateBoundError()
	}
	var bodies, families int
	for _, selector := range selectors {
		switch selector.Kind {
		case LargeImageBlockBodyV1:
			bodies++
		case LargeImageUndoFamilyV1:
			families++
		}
	}
	if bodies > 1440 || families > 1440 {
		return updateBoundError()
	}
	return nil
}

func largeSelectorOrdered(previous, selector LargeImageSelectorV1) bool {
	if previous.Kind != selector.Kind {
		return previous.Kind < selector.Kind
	}
	return bytes.Compare(previous.Hash[:], selector.Hash[:]) < 0
}

func largeSelectorContains(selectors []LargeImageSelectorV1, row ownedConsulted) bool {
	// Both lists are bounded; selectors are located by binary search, never by member scans.
	lo, hi := 0, len(selectors)
	for lo < hi {
		mid := lo+(hi-lo)/2
		selector := selectors[mid]
		if largeSelectorBeforeRow(selector, row) {
			lo = mid+1
		} else {
			hi = mid
		}
	}
	if lo == len(selectors) {
		return false
	}
	selector := selectors[lo]
	if largeImageRank(selector.Kind) != row.dbi.Rank {
		return false
	}
	if selector.Kind == LargeImageBlockBodyV1 {
		return bytes.Equal(selector.Hash[:], row.key)
	}
	return bytes.HasPrefix(row.key, selector.Hash[:])
}

func largeSelectorBeforeRow(selector LargeImageSelectorV1, row ownedConsulted) bool {
	rank := largeImageRank(selector.Kind)
	if rank != row.dbi.Rank {
		return rank < row.dbi.Rank
	}
	key := row.key
	if len(key) > 32 {
		key = key[:32]
	}
	return bytes.Compare(selector.Hash[:], key) < 0
}

func updateOwnedLarge(batch Batch, consulted []ownedConsulted, maxKey uint64) (largeImageScope, error) {
	selectors := batch.LargeConsulted
	if err := largeSelectorCounts(selectors); err != nil {
		return largeImageScope{}, err
	}
	for i, selector := range selectors {
		if largeImageRank(selector.Kind) == 0 {
			return largeImageScope{}, updateInvalidBatch()
		}
		if i != 0 && !largeSelectorOrdered(selectors[i-1], selector) {
			return largeImageScope{}, updateInvalidBatch()
		}
	}
	for _, row := range consulted {
		if largeSelectorContains(selectors, row) {
			return largeImageScope{}, updateInvalidBatch()
		}
	}
	return largeImageScope{selectors: append([]LargeImageSelectorV1(nil), selectors...), maxKey: maxKey}, nil
}

type largeResidualStream struct {
	reader *Reader
	selector LargeImageSelectorV1
	seek []byte
	plan []ownedMutation
	target int
	done bool
}

func (stream *largeResidualStream) excluded(key []byte) bool {
	rank := largeImageRank(stream.selector.Kind)
	for stream.target < len(stream.plan) {
		mutation := stream.plan[stream.target]
		if !updateKeyOrdered(mutation.dbi.Rank, mutation.key, rank, key) {
			return mutation.dbi.Rank == rank && bytes.Equal(mutation.key, key)
		}
		stream.target++
	}
	return false
}

func (stream *largeResidualStream) next() (largeNativeRow, error) {
	for !stream.done {
		row, err := stream.reader.largeNext(stream.selector, stream.seek)
		if err != nil || row.done {
			return row, err
		}
		stream.done = stream.selector.Kind == LargeImageBlockBodyV1
		stream.seek = largeImageAdvance(row.key, stream.reader.maxKey)
		if !stream.excluded(row.key) {
			return row, nil
		}
	}
	return largeNativeRow{done: true}, nil
}

func largeImagesEqual(a, b updateImage) bool {
	if a.present != b.present || a.length != b.length {
		return false
	}
	length := uint64(a.length)
	for offset := uint64(0); offset < length; {
		window := min(uint64(65_536), length-offset)
		left := unsafe.Slice((*byte)(unsafe.Add(a.bytes, uintptr(offset))), int(window))
		right := unsafe.Slice((*byte)(unsafe.Add(b.bytes, uintptr(offset))), int(window))
		if !bytes.Equal(left, right) {
			return false
		}
		offset += window
	}
	return true
}

func largeDomainEqual(old, candidate *Reader, selector LargeImageSelectorV1, plan []ownedMutation) (bool, error) {
	start := sort.Search(len(plan), func(i int) bool {
		return !updateKeyOrdered(plan[i].dbi.Rank, plan[i].key, largeImageRank(selector.Kind), selector.Hash[:])
	})
	left := largeResidualStream{reader: old, selector: selector, seek: selector.Hash[:], plan: plan[start:]}
	right := largeResidualStream{reader: candidate, selector: selector, seek: selector.Hash[:], plan: plan[start:]}
	equal := true
	for {
		a, err := left.next()
		if err != nil {
			return false, err
		}
		b, err := right.next()
		if err != nil {
			return false, err
		}
		if a.done && b.done {
			return equal, nil
		}
		if a.done != b.done || !bytes.Equal(a.key, b.key) || !largeImagesEqual(a.image, b.image) {
			equal = false
		}
	}
}

func largeResidualEqual(old, candidate *Reader, scope largeImageScope, plan []ownedMutation) (bool, error) {
	equal := true
	for _, selector := range scope.selectors {
		match, err := largeDomainEqual(old, candidate, selector, plan)
		if err != nil {
			return false, err
		}
		equal = equal && match
	}
	return equal, nil
}
