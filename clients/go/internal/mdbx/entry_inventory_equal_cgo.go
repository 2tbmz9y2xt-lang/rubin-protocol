//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

/*
#include "../../../../third_party/libmdbx/mdbx.h"
*/
import "C"

import "bytes"

// ownV1 rebinds the descriptor after the single ordinary Pair clone. No public
// stream, original target borrow, or operation is retained into composition.
func (s *entryInventoryStateV1) ownV1(plan *treePlanV1) {
	s.reader.getMu.Lock()
	s.nextBytes = plan.pair[0].literal
	s.decode[1], s.inspection[1] = authorityDecodeControl{}, authorityInspection{}
	entryDecodeControlV1(&s.decode[1])
	s.authority[1], _ = decodeTreeAuthorityV1(s.nextBytes, &s.decode[1], &s.inspection[1])
	s.mutations, s.consulted = nil, nil
	s.reader.getMu.Unlock()
}

// equalV1 replays ORIGINAL selection with exclusive fresh private Readers.
// Every source is retired before its caller can abort a strict read snapshot.
func (s *entryInventoryStateV1) equalV1(candidate *C.MDBX_txn, plan *treePlanV1) (bool, error) {
	s.reader.getMu.Lock()
	original := s.reader
	before, after := newReader(s.entry.old, original.dbis), newReader(candidate, original.dbis)
	for _, r := range [2]*Reader{before, after} {
		r.format, r.databaseID, r.maxKey = original.format, original.databaseID, s.maxKey
		r.ownerVerified = original.ownerVerified
		r.active.Store(true)
	}
	var cursor entryCursorV1
	var context EntryInventoryRowV1
	left, right := &entryStreamV1{}, &entryStreamV1{seek: make([]byte, s.maxKey)}
	s.stream, s.access.key = left, s.failure.Prefix
	w := entryWalkV1{s: s, old: before, candidate: after, stream: left, other: right, cursor: &cursor, context: &context, plan: plan, equal: true}
	defer func() {
		*right = entryStreamV1{}
		s.clearSourcesV1()
		before.active.Store(false)
		after.active.Store(false)
		before.txn, after.txn = nil, nil
		s.reader.getMu.Unlock()
	}()
	err := w.runV1()
	if err == errEntryStoppedV1 {
		err = s.failure.SourceError
	}
	return w.equal && !s.failed, err
}

func (w *entryWalkV1) operationV1() engineOperation {
	if w.candidate != nil {
		return operationUpdate
	}
	return operationGet
}

func (w *entryWalkV1) pointCompareV1(row *EntryInventoryRowV1, key []byte, image *updateImage) error {
	if w.candidate == nil {
		return nil
	}
	rank := entryRankV1(row.Artifact)
	if canonicalTargetIndex(w.plan.pair, rank, key) >= 0 || obsoleteConsultedContains(w.plan.consulted, rank, key) {
		return nil
	}
	actual, err := w.candidate.obsoletePoint(rank, key, operationUpdate)
	if err != nil {
		return w.s.stopV1(1, err)
	}
	w.equal = largeRowsEqual(largeNativeRow{image: *image}, largeNativeRow{image: actual}) && w.equal
	return nil
}

// Candidate-only keys and both exhaustion observations remain in the fold.
func (w *entryWalkV1) scanCompareV1(row *EntryInventoryRowV1) error {
	if w.candidate == nil {
		return nil
	}
	left, right := w.stream, w.other
	for {
		right.row = largeNativeRow{}
		if err := w.fetchV1(right, row); err != nil {
			return err
		}
		if right.done {
			w.equal = left.done && w.equal
			return nil
		}
		if !left.done && bytes.Compare(right.row.key, left.row.key) >= 0 {
			w.equal = obsoleteRowsEqual(left.row, right.row, left.domain.rank, w.plan.consulted) && w.equal
			return nil
		}
		w.equal = false
		right.seek = entrySuccessorV1(right.seek, right.row.key)
	}
}

func (w *entryWalkV1) advanceOtherV1() {
	if w.other != nil {
		w.other.row = largeNativeRow{}
		w.other.seek = w.other.seek[:copy(w.other.seek[:cap(w.other.seek)], w.stream.seek)]
	}
}

func (c *treeComposeV1) entryMatchV1(diagnostic string) error {
	w := c.writer
	if w.plan.inventory == nil {
		return nil
	}
	equal, err := w.plan.inventory.equalV1(w.t.write, w.plan)
	if err == nil && !equal {
		return adapterError(operationUpdate, EngineStateMismatch, codeProblem, diagnostic, nil)
	}
	return err
}

// entryTruthV1 extends the existing single-snapshot truth callback. False
// predicates never skip a subsequent required ordinary or residual source.
func (c *treeComposeV1) entryTruthV1(read *C.MDBX_txn, _ error) (CommitTruth, error) {
	w, p := c.writer, c.writer.plan
	old, next, err := updateNativeReadbackTargets(w.old, read, w.s.dbis, p.pair, w.t.references)
	if err != nil {
		return CommitTruthUnknown, err
	}
	old, next, err = updateNativeReadbackReferences(w.old, read, w.s.dbis, p.pair, w.t.references, old, next)
	if err != nil {
		return CommitTruthUnknown, err
	}
	old, next, err = updateNativeReadbackScoped(w.old, read, w.s.dbis, p.pair, p.consulted, old, next)
	if err != nil {
		return CommitTruthUnknown, err
	}
	residual, err := p.inventory.equalV1(read, p)
	if err != nil {
		return CommitTruthUnknown, err
	}
	switch {
	case !residual:
		return CommitTruthUnknown, nil
	case old:
		return CommitTruthOld, nil
	case next:
		return CommitTruthNew, nil
	default:
		return CommitTruthUnknown, nil
	}
}
